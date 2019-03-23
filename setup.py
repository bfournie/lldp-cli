#!/usr/bin/env python

PROJECT = 'lldpreport'

VERSION = '0.1'

from setuptools import setup, find_packages

try:
    long_description = open('README.rst', 'rt').read()
except IOError:
    long_description = ''

setup(
    name=PROJECT,
    version=VERSION,

    description='LLDP report tool to show switch configuration',
    long_description=long_description,

    url='https://github.com/openstack/triple-common/lldpreport',

    classifiers=['Development Status :: 3 - Alpha',
                 'License :: OSI Approved :: Apache Software License',
                 'Programming Language :: Python',
                 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 3.2',
                 'Intended Audience :: Developers',
                 'Environment :: Console',
                 ],

    platforms=['Any'],

    scripts=[],

    provides=[],

    namespace_packages=[],
    packages=find_packages(),
    include_package_data=True,

    entry_points={
        'console_scripts': [
            'lldpreport = lldpreport.main:main'
        ],
        'lldpcommands': [
            'interface list = lldpreport.lldp:InterfaceList',
            'interface show = lldpreport.lldp:InterfaceShow',
            'vlan list = lldpreport.lldp:VlanShow',
            'save = lldpreport.lldp:Save',
            'field show = lldpreport.lldp:FieldShow',
        ],
    },

    zip_safe=False,
)
