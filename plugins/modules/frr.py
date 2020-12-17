#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lee Chee Kean <cklee28@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'TBD'}

DOCUMENTATION = """
---
module: pfsensible.core.frr
version_added: "2.10"
author: Lee Chee Kean (@cklee288)
short_description: Manage ckSense frr global
description:
  - Manage ckSense frr global
notes:
options:
  enable:
    description: enable frr or not
    required: false
    type: str
    choices: [ "on", "" ]
    default: ""
  password:
    description: password to access frr daemon.
    required: true
    type: str
  carpstatusvid:
    description: CARP vhid interface used to defined frr daemon. When in BACKUP status, frr will not be started
    required: false
    type: str
    default: none
  logging:
    description: enable logging 
    required: false
    type: str
    choices: [ "on", "" ]
    default: "" 
  routerid:
    description: router IP of frr
    required: false
    type: str
    choices: [ "on", "" ]
    default: "" 
  ignoreipsecrestart:
    description: ignore IPsec restart events.
    choices: [ "on", "" ]
    default: "" 
    type: str
  maintainasis:
    description: copy existing parameter of frr global
    choices: [ "yes", "no" ]
    type: str
  routevalue1-20:
    description: route ip network (network/bit mask).
    required: false
    type: str
    default: "" 
  routetarget1-20:
    description: gateway or interface (format: gw|<gw name> / if|<interface name>).
    default: false
    type: str
    default: "" 
  state:
    description: State in which to leave the frr
    choices: [ "present", "absent" ]
    default: present
    type: str
"""

EXAMPLES = """
- name: enable frr static route
  pfsensible.core.frr:
    enable: on
    password: mypassword
    carpstatusvid: none
    logging: off
    routevalue1: "10.0.1.0/24"
    routetarget1: if|opt3

- name: on frr maintain as is
  pfsensible.core.frr:
    enable: on
    password: myansiblepass
    maintainasis: yes
  become: yes


- name: disable frr 
  pfsensible.core.frr:
    enable: ""
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: [" frr setting enable='on', .... "]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.frr import PFSenseFrrModule, FRR_ARGUMENT_SPEC, FRR_REQUIRED_IF


def main():
    module = AnsibleModule(
        argument_spec=FRR_ARGUMENT_SPEC,
        required_if=FRR_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseFrrModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
