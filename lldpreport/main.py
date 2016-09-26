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

import sys

from cliff.app import App
from cliff.commandmanager import CommandManager

class LldpReport(App):

    def __init__(self):
        super(LldpReport, self).__init__(
            description='LLDP report tool',
            version='0.1',
            command_manager=CommandManager('lldpcommands'),
            deferred_help=True,
            )

def main(argv=sys.argv[1:]):
    myapp = LldpReport()
    return myapp.run(argv)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
