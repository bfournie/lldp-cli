# Copyright 2016 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import binascii
import json
import os
import netaddr
import subprocess
import sys
import logging
from collections import defaultdict

from cliff.command import Command
from cliff.lister import Lister
from cliff.show import ShowOne
import ironicclient.client as ironic_client
import ironic_inspector_client
from os_cloud_config.utils import clients

test = False
useCommand = False

# TLV types
LLDP_TLV_TYPE_CHASSIS_ID = 1
LLDP_TLV_TYPE_PORT_ID = 2
LLDP_TYPE_TTL = 3
LLDP_TYPE_PORT_DESCRIPTION = 4
LLDP_TYPE_SYS_NAME = 5
LLDP_TYPE_SYS_DESCRIPTION = 6
LLDP_TYPE_SYS_CAPABILITIES = 7
LLDP_TYPE_MGMT_ADDRESS = 8
LLDP_TYPE_ORG_SPECIFIC = 127

# 802.1 defines from Annex E of IEEE Std 802.1AB-2009
LLDP_802dot1_OUI = "0080c2"
# subtypes
dot1_PORT_VLANID = 1
dot1_PORT_PROTOCOL_VLANID = 2  # TODO
dot1_VLAN_NAME = 3
dot1_PROTOCOL_IDENTITY = 4
dot1_VID_USAGE = 5  # TODO
dot1_MANAGEMENT_VID = 6
dot1_LINK_AGGREGATION = 7

# 802.3 defines from Annex F of IEEE Std 802.1AB-2009
LLDP_802dot3_OUI = "00120f"
# subtypes
dot3_MACPHY_CONFIG_STATUS = 1
dot3_POWER_VIA_MDI = 2  # TODO
dot3_LINK_AGGREGATION = 3  # DEPRECATED so not supported
dot3_MTU = 4

# Vendor specific
JUNIPER_OUI = "009069"
# subtype
JUNIPER_CHASSIS_TYPE = 1


class TLV():
    """Base TLV class."""

    def __init__(self):
        self.name = ""
        self.value = ""
        self.field = ""

    def output(self):
        print("\t" + self.name + ": " + self.value)


class ChassisID_TLV(TLV):
    """ChassisID_TLV class"""
    SUBTYPE_CHASSIS_COMP = 1
    SUBTYPE_IFALIAS = 2
    SUBTYPE_PORT_COMP = 3
    SUBTYPE_MAC = 4
    SUBTYPE_NETWORK_ADDRESS = 5
    SUBTYPE_IFNAME = 6
    SUBTYPE_LOCAL = 7

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Chassis ID"
        self.field = "switch_chassis_id"

        if data[0] == self.SUBTYPE_MAC:
            mac = netaddr.EUI(binascii.hexlify(data[1:]).decode())
            mac.dialect = netaddr.mac_unix
            self.value = str(mac)
        else:
            # treat all other types as strings
            self.value = data[1:].decode()


class PortID_TLV(TLV):
    """PortID_TLV class"""
    SUBTYPE_IFALIAS = 1
    SUBTYPE_PORT_COMP = 1
    SUBTYPE_MAC = 3
    SUBTYPE_NETWORK_ADDRESS = 4
    SUBTYPE_IFNAME = 5
    SUBTYPE_AGENT_CIRCUIT_ID = 6
    SUBTYPE_LOCAL = 7

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port ID"
        self.field = "switch_port_id"

        if data[0] == self.SUBTYPE_MAC:
            self.value = str(
                netaddr.EUI(binascii.hexlify(data[1:]).decode()))
        elif data[0] == self.SUBTYPE_NETWORK_ADDRESS:
            self.value = str(
                netaddr.IPAddress(binascii.hexlify(data[1:]).decode()))
        else:
            # treat all other types as strings
            self.value = data[1:].decode()

class InterfaceMacAddress(TLV):
    """InterfaceMacAddress class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Interface MAC Address"
        self.field = "interface_mac_address"

        self.value = data


class SysName_TLV(TLV):
    """SysName_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "System Name"
        self.field = "switch_system_name"

        self.value = data[0:].decode()


class SysDesc_TLV(TLV):
    """SysDesc_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "System Description"
        self.field = "switch_system_description"

        self.value = data[0:].decode()


class SysCapabilities_TLV(TLV):
    """SysCapabilities_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "System Capabilities"
        self.field = "switch_system_capabilities"

        sys_cap = []
        b = data[1]
        if b & 0x02:
            sys_cap.append('Repeater')
        if b & 0x04:
            sys_cap.append('Bridge')
        if b & 0x08:
            sys_cap.append('WLAN')
        if b & 0x10:
            sys_cap.append('Router')
        if b & 0x20:
            sys_cap.append('Telephone')
        if b & 0x40:
            sys_cap.append('DOCSIS cable device')
        if b & 0x80:
            sys_cap.append('Station')
        # TODO - look at this again...
        if b & 0x100:
            sys_cap.append('C-Vlan')
        if b & 0x200:
            sys_cap.append('S-Vlan')
        if b & 0x400:
            sys_cap.append('TPMR')

        self.value = str(sys_cap)

class MgmtAddress_TLV(TLV):
    """MgmtAddress_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)

        # TODO

        self.value = data[0:].decode()


class PortDesc_TLV(TLV):
    """PortDesc_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Description"
        self.field = "switch_port_description"

        self.value = data[0:].decode()


class VlanId_TLV(TLV):
    """VlanId_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Untagged Vlan ID"
        self.field = "switch_port_untagged_vlan_id"

        # TODO - can this be simplified?
        self.value = "%d" % int(binascii.b2a_hex(data[0:2]).decode(), 16)


class VlanName_TLV(TLV):
    """VlanName_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Vlan Name (ID)"
        self.field = "switch_port_vlan_name_and_id"

        vlan_id = int(binascii.b2a_hex(data[0:2]).decode(), 16)
        vlan_name = data[3:].decode()

        self.value = "%s (%d)" % (vlan_name, vlan_id)


class VlanNameList_TLV(TLV):
    """VlanNameList_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Vlans"
        self.field = "switch_port_vlans"

        self.value = ""
        self.vlan_list = []

    def add_vlan(self, vlan):
        self.vlan_list.append(vlan.value)

        self.value = str(self.vlan_list)


class ProtocolId_TLV(TLV):
    """ProtocolId_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Protocol Identity"
        self.field = "switch_protocol_identify"

        self.value = data[1:].decode()


class MgmtVlanId_TLV(TLV):
    """MgmtVlanId_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Management Vlan ID"
        self.field = "switch_port_management_vlanid"

        self.value = "%d" % int(binascii.b2a_hex(data[0:2]).decode(), 16)


class LinkAggregationConfig_TLV(TLV):
    """LinkAggregationConfig_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Link Aggregation Support"
        self.field = "switch_port_link_aggregation_support"

        self.value = "%s" % str((data[0] & 0x01) != 0)


class LinkAggregationStatus_TLV(TLV):
    """LinkAggregationStatus_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Link Aggregation Enabled"
        self.field = "switch_port_link_aggregation_enabled"

        self.value = "%s" % str((data[0] & 0x02) != 0)


class LinkAggregationPortId_TLV(TLV):
    """LinkAggregationPortId_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Link Aggregation ID"
        self.field = "switch_port_link_aggregation_id"

        port_id = int(binascii.b2a_hex(data[0:3]).decode(), 16)

        self.value = "%d" % port_id


class Autoneg_Config_TLV(TLV):
    """Autoneg_Config_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Autonegotiation Support"
        self.field = "switch_port_autonegotiation_support"

        self.value = "%s" % str(data[0] & 0x01 != 0)


class Autoneg_Status_TLV(TLV):
    """Autoneg_Status_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Autonegotiation Enabled"
        self.field = "switch_port_autonegotiation_enabled"

        self.value = "%s" % str(data[0] & 0x02 != 0)


class Pmd_Autoneg_Config_TLV(TLV):
    """Pmd_Autoneg_config_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Physical Media Capabilities"
        self.field = "switch_port_physical_capabilities"

        # Get PMD autonegotiation capability using BITS
        # psuedotype encoding, see section 8.1 of IEEE Std 802.1AB-2009
        # and Interpretation Request #1
        pmd_autoneg = []
        if data[0] & 0x40:
            pmd_autoneg.append('10BASE-T hdx')
        if data[0] & 0x20:
            pmd_autoneg.append('10BASE-T fdx')
        if data[0] & 0x10:
            pmd_autoneg.append('10BASE-T4')
        if data[0] & 0x08:
            pmd_autoneg.append('100Base-TX hdx')
        if data[0] & 0x04:
            pmd_autoneg.append('100BASE-TX fdx')
        if data[0] & 0x02:
            pmd_autoneg.append('100Base-T2 hdx')
        if data[0] & 0x01:
            pmd_autoneg.append('100BASE-T2 fdx')
        if data[1] & 0x80:
            pmd_autoneg.append('PAUSE fdx')
        if data[1] & 0x40:
            pmd_autoneg.append('Asymmetric PAUSE fdx')
        if data[1] & 0x20:
            pmd_autoneg.append('Symmetric PAUSE fdx')
        if data[1] & 0x10:
            pmd_autoneg.append('Asymmetric and Symmetric PAUSE fdx')
        if data[1] & 0x08:
            pmd_autoneg.append('1000Base-T hdx')
        if data[1] & 0x04:
            pmd_autoneg.append('1000BASE-T fdx')
        if data[1] & 0x02:
            pmd_autoneg.append('1000Base-T hdx')
        if data[1] & 0x01:
            pmd_autoneg.append('1000BASE-T fdx')

        self.value = str(pmd_autoneg)


class Mau_Type_TLV(TLV):
    """Mau_Type_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port Media Attachment Unit Type"
        self.field = "switch_port_mau_type"

        # MAU types, from RFC 4836
        mau_types = {
            0: "Unknown",
            1: "AUI",
            2: "10BASE - 5",
            3: "FOIRL",
            4: "10BASE - 2",
            5: "10BASE - T duplex mode unknown",
            6: "10BASE - FP",
            7: "10BASE - FB",
            8: "10BASE - FL duplex mode unknown",
            9: "10BROAD36",
            10: "10BASE - T half duplex",
            11: "10BASE - T full duplex",
            12: "10BASE - FL half duplex",
            13: "10BASE - FL full duplex",
            14: "100 BASE - T4",
            15: "100BASE - TX half duplex",
            16: "100BASE - TX full duplex",
            17: "100BASE - FX half duplex",
            18: "100BASE - FX full duplex",
            19: "100BASE - T2 half duplex",
            20: "100BASE - T2 full duplex",
            21: "1000BASE - X half duplex",
            22: "1000BASE - X full duplex",
            23: "1000BASE - LX half duplex",
            24: "1000BASE - LX full duplex",
            25: "1000BASE - SX half duplex",
            26: "1000BASE - SX full duplex",
            27: "1000BASE - CX half duplex",
            28: "1000BASE - CX full duplex",
            29: "1000BASE - T half duplex",
            30: "1000BASE - T full duplex",
            31: "10GBASE - X",
            32: "10GBASE - LX4",
            33: "10GBASE - R",
            34: "10GBASE - ER",
            35: "10GBASE - LR",
            36: "10GBASE - SR",
            37: "10GBASE - W",
            38: "10GBASE - EW",
            39: "10GBASE - LW",
            40: "10GBASE - SW",
            41: "10GBASE - CX4",
            42: "2BASE - TL",
            43: "10PASS - TS",
            44: "100BASE - BX10D",
            45: "100BASE - BX10U",
            46: "100BASE - LX10",
            47: "1000BASE - BX10D",
            48: "1000BASE - BX10U",
            49: "1000BASE - LX10",
            50: "1000BASE - PX10D",
            51: "1000BASE - PX10U",
            52: "1000BASE - PX20D",
            53: "1000BASE - PX20U",
        }

        self.value = mau_types[data[0]]


class MTU_TLV(TLV):
    """MTU_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port MTU"
        self.field = "switch_port_mtu"

        # TODO - can this be simplified?
        self.value = "%d" % int(binascii.b2a_hex(data[0:2]).decode(), 16)


class MED_Capabilities_TLV(TLV):
        """MED_Capabilities_TLV class"""

        def __init__(self, data):
            TLV.__init__(self)
            self.name = "Port MED Capabilities"
            self.field = "switch_port_med_capabilities"

            med_capabilities = []
            if data[1] & 0x20:
                med_capabilities.append('inventory')
            if data[1] & 0x10:
                med_capabilities.append('extended power via MDI-PD')
            if data[1] & 0x08:
                med_capabilities.append('extended power via MDI-PSE')
            if data[1] & 0x04:
                med_capabilities.append('location')
            if data[1] & 0x02:
                med_capabilities.append('network policy')
            if data[1] & 0x01:
                med_capabilities.append('LLDP_MED capabilities')

            self.value = str(med_capabilities)


class MED_Device_Type_TLV(TLV):
    """MED_Device_type_TLV class"""

    def __init__(self, data):
        TLV.__init__(self)
        self.name = "Port MED Device Type"
        self.field = "switch_port_med_device_type"

        device_type = ""
        if data[0] == 0:
            device_type = "Not defined"
        elif data[0] == 1:
            device_type = "Endpoint class I"
        elif data[0] == 2:
            device_type = "Endpoint class II"
        elif data[0] == 3:
            device_type = "Endpoint class III"
        elif data[0] == 4:
            device_type = "Network connectivity"

        self.value = device_type


class Juniper_chassis_TLV(TLV):
        """Juniper_chassis_TLV class"""

        def __init__(self, data):
            TLV.__init__(self)
            self.name = "VendorChassis Identifier"
            self.field = "switch_vendor_chassis_identifier"

            self.value = "%s" % str(data[0:].decode())

def env(*args, **kwargs):
    """Returns the first environment variable set.

    If all are empty, defaults to '' or keyword arg `default`.
    """
    for arg in args:
        value = os.environ.get(arg)
        if value:
            return value
    return kwargs.get('default', '')


class LldpReporter():

    def get_ironic_lldp_data(self, node_id, keystone_client):
        # Return list of interface data in json format
        if test:
            filename = "./interfaces-node-1.json"
            with open(filename, 'r') as f:
                contents = f.read()
                return contents

        elif useCommand:
            filename = "tmp"
            cmd = "/bin/openstack baremetal introspection data save " + \
                  node_id + " > " + filename
            print("Running cmd " + cmd)

            try:
                p = subprocess.Popen(cmd, shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

            except OSError as e:
                print("Error running introspection data save, Error: %s" % e)
                exit()

            stdout, stderr = p.communicate()
            if p.returncode != 0:
                print(('Error running introspection data save.'
                       'Stdout: "%(stdout)s". Stderr: %(stderr)s') %
                      {'stdout': stdout, 'stderr': stderr})

            with open(filename, 'r') as f:
                contents = f.read()
                return contents

        else:
            inspector_url = keystone_client.service_catalog.url_for(
                service_type="baremetal-introspection",
                endpoint_type="publicURL")

            client = ironic_inspector_client.ClientV1(
                session=keystone_client.session,
                inspector_url=inspector_url)

            introspected_data = client.get_data(node_id)
            # data = json.dump(introspected_data, sys.stdout)
            return introspected_data

    def get_lldp_interface_data(self, interface_data, node_id, int_name = None):
        interfaces = {}
        # List of dictionaries is returned, each lldp entry is
        # list of lists
        found = False
        for info in interface_data:
            if (int_name is not None) and (int_name != info['name']):
                continue

            found = True
            obj_list = []
            vlan_name_list = None
            nic = info["name"]

            # Get mac_address which is in interface, not in lldp
            mac = info["mac_address"]
            tlv = InterfaceMacAddress(mac)
            obj_list.append(tlv)

            tlv_entry = info["lldp"]
            for tlv_type, tlv_value in tlv_entry:

                try:
                    data = bytearray(binascii.unhexlify(tlv_value))
                except TypeError:
                    LOG.warning(_LW("TLV value for TLV type %d not in correct"
                                "format, TLV value must be in hexidecimal"),
                                tlv_type)
                    continue

                if tlv_type == LLDP_TLV_TYPE_CHASSIS_ID:
                    tlv = ChassisID_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TLV_TYPE_PORT_ID:
                    tlv = PortID_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TYPE_PORT_DESCRIPTION:
                    tlv = PortDesc_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TYPE_SYS_NAME:
                    tlv = SysName_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TYPE_SYS_DESCRIPTION:
                    tlv = SysDesc_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TYPE_SYS_CAPABILITIES:
                    tlv = SysCapabilities_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TYPE_MGMT_ADDRESS:
                    tlv = MgmtAddress_TLV(data)
                    obj_list.append(tlv)

                elif tlv_type == LLDP_TYPE_ORG_SPECIFIC:
                    oui = str((binascii.hexlify(data[0:3]).decode()))
                    subtype = data[3]
                    if oui == LLDP_802dot1_OUI:
                        if subtype == dot1_PORT_VLANID:
                            tlv = VlanId_TLV(data[4:])
                            obj_list.append(tlv)
                        elif subtype == dot1_VLAN_NAME:
                            vlan = VlanName_TLV(data[4:])
                            obj_list.append(vlan)
                            if vlan_name_list is None:
                                vlan_name_list = VlanNameList_TLV(data[4:])
                                obj_list.append(vlan_name_list)
                            vlan_name_list.add_vlan(vlan)
                        elif subtype == dot1_PROTOCOL_IDENTITY:
                            tlv = ProtocolId_TLV(data[4:])
                            obj_list.append(tlv)
                        elif subtype == dot1_MANAGEMENT_VID:
                            tlv = MgmtVlanId_TLV(data[4:])
                            obj_list.append(tlv)
                        elif subtype == dot1_LINK_AGGREGATION:
                            tlv = LinkAggregationConfig_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = LinkAggregationStatus_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = LinkAggregationPortId_TLV(data[5:])
                            obj_list.append(tlv)
                        else:
                            print("Unexpected 802.1 subtype detected %d" %
                                  subtype)

                    elif oui == LLDP_802dot3_OUI:
                        if subtype == dot3_MACPHY_CONFIG_STATUS:
                            tlv = Autoneg_Config_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = Autoneg_Status_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = Pmd_Autoneg_Config_TLV(data[5:])
                            obj_list.append(tlv)
                            tlv = Mau_Type_TLV(data[7:8])
                            obj_list.append(tlv)
                        elif subtype == dot3_MTU:
                            tlv = MTU_TLV(data[4:])
                            obj_list.append(tlv)
                        elif subtype == dot3_LINK_AGGREGATION:
                            # TLV has been deprecated, but still in use
                            tlv = LinkAggregationConfig_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = LinkAggregationStatus_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = LinkAggregationPortId_TLV(data[5:])
                            obj_list.append(tlv)
                        else:
                            print("Unexpected 802.3 subtype detected %d"
                                  % subtype)

                    elif oui == LLDP_MED_OUI:
                        if subtype == MEDIA_ENDPOINT_CAPABILITIES:
                            tlv = MED_Capabilities_TLV(data[4:])
                            obj_list.append(tlv)
                            tlv = MED_Device_Type_TLV(data[6:])
                            obj_list.append(tlv)
                        else:
                            print("Unexpected LLDP_MED subtype detected %d"
                                  % subtype)

                    elif oui == JUNIPER_OUI:
                        if subtype == JUNIPER_CHASSIS_TYPE:
                            tlv = Juniper_chassis_TLV(data[4:])
                            obj_list.append(tlv)
                        else:
                            print("Unexpected Juniper subtype detected %d"
                                  % subtype)

            interfaces[nic] = obj_list

        if not found:
            print("Could not find interface " + int_name + " for node " + node_id)
            return None

        return interfaces


    def get_lldp_report(self, keystone_client, uuid, int_name = None):

        json_data = self.get_ironic_lldp_data(uuid, keystone_client)

        # json data is list of dictionaries, lldp data is list of lists
        interfaces = json_data['inventory']['interfaces']

        return self.get_lldp_interface_data(interfaces, uuid, int_name)

    def get_interfaces_per_node(self, keystone_client, uuid):

        json_data = self.get_ironic_lldp_data(uuid, keystone_client)

        # json data is list of dictionaries, lldp data is list of lists
        all_interfaces = json_data['inventory']['interfaces']

        intf_list = []
        for info in all_interfaces:
            intf_list.append(info['name'])

        return intf_list

    def get_os_config(self, argv):

        os_username = env('OS_USERNAME')
        os_password = env('OS_PASSWORD')
        os_auth_url = env('OS_AUTH_URL')
        os_tenant_name = env('OS_TENANT_NAME')

        kwargs = {
            'os_username': os_username,
            'os_password': os_password,
            'os_auth_url': os_auth_url,
            'os_tenant_name': os_tenant_name
        }

        return kwargs

    def get_interface_report(self, argv):

        # Prevent log info messages for HTTP requests
        logging.getLogger("requests").setLevel(logging.WARNING)

        os_config = self.get_os_config(argv)

        ironic = ironic_client.get_client(1, **os_config)

        keystone_client = clients.get_keystone_client(os_config['os_username'],
                                                      os_config['os_password'],
                                                      os_config['os_tenant_name'],
                                                      os_config['os_auth_url'])

        interface_report = self.get_lldp_report(keystone_client, argv.node, argv.interface)

        return interface_report

    def get_interface_lists(self, argv):

        # Prevent log info messages for HTTP requests
        logging.getLogger("requests").setLevel(logging.WARNING)

        os_config = self.get_os_config(argv)

        ironic = ironic_client.get_client(1, **os_config)

        keystone_client = clients.get_keystone_client(os_config['os_username'],
                                                      os_config['os_password'],
                                                      os_config['os_tenant_name'],
                                                      os_config['os_auth_url'])
        interfaces = {}
        for node in ironic.node.list():
            if argv.node is not None and argv.node != node.uuid:
                continue

            # Get report for all interfaces on this node
            intf_per_node = self.get_interfaces_per_node(keystone_client, node.uuid)

            interfaces[node.uuid] = intf_per_node

        return interfaces

    def get_full_report(self, argv):

        logging.getLogger("requests").setLevel(logging.WARNING)

        os_config = self.get_os_config(argv)

        ironic = ironic_client.get_client(1, **os_config)

        keystone_client = clients.get_keystone_client(os_config['os_username'],
                                                      os_config['os_password'],
                                                      os_config['os_tenant_name'],
                                                      os_config['os_auth_url'])

        full_report = {}
        for node in ironic.node.list():
            if argv.node is not None and argv.node != node.uuid:
                continue

            if argv.interface is not None:
                node_report = self.get_lldp_report(keystone_client, node.uuid, argv.interface)
            else:
                # Get report for all interfaces on this node
                node_report = self.get_lldp_report(keystone_client, node.uuid)

            full_report[node.uuid] = node_report

        return full_report


class InterfaceList(Lister):
    "show a list of interfaces for each node"

    def get_parser(self, prog_name):
        parser = super(InterfaceList, self).get_parser(prog_name)
        parser.add_argument("--node", metavar="<node>",
                            help="name or UUID of the node")
        return parser

    def take_action(self, parsed_args):
        report = LldpReporter().get_interface_lists(parsed_args)

        return (("Node", "Interfaces"),
                 list((node_name, sorted(intf_list)) for node_name, intf_list in report.items()))


class InterfaceShow(ShowOne):
    "show all LLDP values for an interface"

    def get_parser(self, prog_name):
        parser = super(InterfaceShow, self).get_parser(prog_name)
        parser.add_argument("node", metavar="<node>",
                            help="name or UUID of the node")
        parser.add_argument("interface", metavar="<interface>",
                            help="interface name")
        return parser

    def take_action(self, parsed_args):
        # Get list of classes
        report = LldpReporter().get_interface_report(parsed_args)

        fields = []
        values = []
        if report is not None:
            fields.append("node")
            values.append(parsed_args.node)
            fields.append("interface")
            values.append(parsed_args.interface)
            for int_name, obj_list in sorted(report.items()):
                # dict has been filtered for "interface" TODO - add check
                for obj in obj_list:
                    if isinstance(obj, VlanName_TLV):
                        continue # show vlans in VlanNameList, not individually
                    fields.append(obj.field)
                    values.append(obj.value)

        return (fields, values)


class VlanList(Lister):
    "show each VLAN and the interfaces where it is configured"

    def get_parser(self, prog_name):
        parser = super(VlanShow, self).get_parser(prog_name)
        parser.add_argument("--node", metavar="<node>",
                            help="name or UUID of the node")
        parser.add_argument("--interface", metavar="<interface>",
                            help="interface name")
        # TODO - take optional vlan name?
        return parser

    def take_action(self, parsed_args):
        report = LldpReporter().get_full_report(parsed_args)

        # Get list of interfaces mapped to vlan and node
        vlans = {}
        if report is not None:
            vlan_dict = defaultdict(lambda: defaultdict(list))
            for node_name, intf_dict in sorted(report.items()):
                for intf_name, obj_list in sorted(intf_dict.items()):
                    for obj in obj_list:
                        if isinstance(obj, VlanName_TLV):
                            vlan_dict[obj.value][node_name].append(intf_name)

            # Reformat interface list suitable for printing
            for vlan_name, port_dict in sorted(vlan_dict.items()):
                interfaces = {}
                for node_name, intf_list in sorted(port_dict.items()):
                    interfaces[node_name] = intf_list
                vlans[vlan_name] = interfaces

        return (("Switch Vlan", "Switch Port Connections"),
                 list((vlan_name, intf_list) for vlan_name, intf_list in sorted(vlans.items())))


class Save(Command):
    "save or display the full LLDP report for all nodes in json format"

    def get_parser(self, prog_name):
        parser = super(Save, self).get_parser(prog_name)
        parser.add_argument("--node", metavar="<node>",
                            help="name or UUID of the node")
        parser.add_argument("--interface", metavar="<interface>",
                            help="interface name")
        parser.add_argument("--file", metavar="<filename>", default=None,
                            help="write output to file")
        return parser

    def take_action(self, parsed_args):
        report = LldpReporter().get_full_report(parsed_args)

        formatted_report = {}
        for node_uuid, intf_dict in sorted(report.items()):
            intfs = {}
            for intf_name, obj_list in sorted(intf_dict.items()):
                bindings = {}
                for obj in obj_list:
                    bindings[obj.field] = obj.value
                intfs[intf_name] = bindings

            formatted_report[node_uuid] = intfs

        if parsed_args.file:
            with open(parsed_args.file, 'wb') as fp:
                json.dump(formatted_report, fp, sort_keys=True)
        else:
            json.dump(formatted_report, sys.stdout, sort_keys=True)


class FieldShow(Lister):
    "show the value of provided field for each node/interfaces"

    def get_parser(self, prog_name):
        parser = super(FieldShow, self).get_parser(prog_name)
        parser.add_argument("field", metavar="<field_name>",
                            help="name of a field shown in the 'interface show' command")
        parser.add_argument("--node", metavar="<node>",
                            help="name or UUID of the node")
        parser.add_argument("--iface", metavar="<iface>",
                            help="interface name")
        return parser

    def take_action(self, parsed_args):
        report = LldpReporter().get_full_report(parsed_args)

        # Get value that matches input field
        values = []
        if report is not None:
            for node_name, intf_dict in sorted(report.items()):
                for intf_name, obj_list in sorted(intf_dict.items()):
                    for obj in obj_list:
                        if obj.field == parsed_args.field:
                            interface = "%s:%s" % (node_name, intf_name)
                            values.append((interface, obj.value))

        # TODO - check that at least one is returned, otherwise indicate invalid field

        return (("Node:Interface", parsed_args.field), values)
