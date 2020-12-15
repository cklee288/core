#!/usr/bin/python
# -*- coding: utf-8 -*-


# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsensible.core.gateway_group
version_added: "2.10"
short_description: Manage ckSense gateway group
description:
  >
    Manage ckSense  
author: CK Lee (@cklee288)
notes:
options:
  name:
    description: The name of the gateway group
    required: true
    type: str
  state:
    description: State in which to leave the gateway group
    required: true
    choices: [ "present", "absent" ]
    type: str
  description:
    description: desciprition of gateway group
    required: false
    type: str
  gateway1-5:
    description:
      >
        The gateway item1-5 with for the gateway group.  This must be in an existing gateway. 
        (which is how ckSense assign as item).
    type: str
    required: false
  priority_gw1-5:
    description:
      >
        The priority of gateway item1-5 for the gateway group.  This must be '1' to '5'. 
        (1 highest preferences, 5 lowest).
    type: str
    required: false
  trigger:
    description:
      >
        Event used to trigger next tier of gateway. This can be
        down (member down), downloss(packet loss), downlatency(high latency) 
        and downlosslatency (packet loss or high latency)
    type: str
    required: false
  descr:
    description:
      >
        description of the gateway group
    type: str
"""

EXAMPLES = """
- name: Add AD Certificate
  pfsensible.core.gateway_group:
    name: gwgrp_gw1fogw2
    gateway1: gw1
    priority_gw1: '1'
    trigger: down
    state: present

- name: Remove gateway group
  pfsensible.core.gateway_group:
    name: gwgrp_gw1fogw2
    state: absent
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create gateway 'gwgrp_gw1fogw2', gateway1='gw1', gateway_pr1="1" trigger='down'", "delete gateway_group 'gwgrp_gw1fogw2'"]
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.gateway_group import PFSenseGatewaygroupModule, GATEWAYGROUP_ARGUMENT_SPEC, GATEWAYGROUP_REQUIRED_IF


def main():
    module = AnsibleModule(
        argument_spec=GATEWAYGROUP_ARGUMENT_SPEC,
        required_if=GATEWAYGROUP_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseGatewaygroupModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()