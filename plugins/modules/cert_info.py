#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lee Chee Kean <cklee28@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '2.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsensible.core.cert_info
version_added: "2.10"
short_description: get ckSense Certificate
description:
  >
    get ckSense Certificate
author: CK Lee (@cklee288)
notes:
options:
  specific:
    description: specific certificate name
    required: false
    default: 'no'
    choices: [ "yes", "no" ]
  exact:
    description: specific certificate name
    required: false
    default: 'no'
    choices: [ "yes", "no" ]
  name:
    description: The name of the Certificate, name can be regular express if exact set to no
    required: false
    option: required if specific as yes.
    type: str
  state:
    description: State in which to leave the Certificate
    required: false
    choices: [ "present", "absent" ]
    default: present
    type: str
"""

EXAMPLES = """
- name: get all certificate info
  pfsensible.core.cert_info:
    specific: no
    state: present

- name: get specific certificate info with exact match
  pfsensible.core.cert:
    specific: "yes"
    exact: "yes"
    name: cert.com-name
    state: present

- name: get specific certificate info with some match
  pfsensible.core.cert:
    specific: "yes"
    exact: "no"
    name: e1-.*.cksdnow.com
    state: present
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule


class pfSenseCERTinfo(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = PFSenseModule(module)
        self.certs = self.pfsense.get_elements('cert')

    def _list_cert(self, name):
        i = 0
        changed = False
        diff = {}
        stdout = []
        results = []
        stderr = None
        for icert in self.certs:
            i = self.pfsense.get_index(icert)
            tempdict = {} 
            if icert.find('descr').text == name:
              tempdict["refid"] = icert.find('refid').text
              tempdict["descr"] = icert.find('descr').text
              tempcert = icert.find('crt').text
              if re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', tempcert):
                  tempdict["crt"] = base64.b64decode(tempcert)      
              results.append(tempdict)
        self.module.exit_json(changed=changed, diff=diff, results=results, stdout=stdout, stderr=stderr)

    def _list_cert_match(self, name):
      # match only portion of the name
        i = 0
        changed = False
        diff = {}
        stdout = []
        results = []
        stderr = None
        for icert in self.certs:
            i = self.pfsense.get_index(icert)
            tempdict = {} 
            if re.match(name, icert.find('descr').text):
              tempdict["refid"] = icert.find('refid').text
              tempdict["descr"] = icert.find('descr').text
              tempcert = icert.find('crt').text
              if re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', tempcert):
                  tempdict["crt"] = base64.b64decode(tempcert)      
              results.append(tempdict)
        self.module.exit_json(changed=changed, diff=diff, results=results, stdout=stdout, stderr=stderr)


    def return_listall(self, cert):
        changed = False
        diff = {}
        stdout = []
        results = []
        stderr = None
        for icert in self.certs:
            tempdict = {} 
            tempdict["refid"] = icert.find('refid').text
            tempdict["descr"] = icert.find('descr').text
            tempcert = icert.find('crt').text
            if re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', tempcert):
                tempdict["crt"] = base64.b64decode(tempcert)      
            results.append(tempdict)
            # cnt += 1
        self.module.exit_json(changed=changed, diff=diff, results=results, stdout=stdout, stderr=stderr)


    def remove(self, cert):
        return None

def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': False, 'type': 'str'},
            'state': {
                'default': 'present',
                'choices': ['present', 'absent']
            },
            'specific': {
                'required': False,
                'default': 'no',
                'choices': ['yes', 'no']
            },
            'exact': {
                'required': False,
                'default': 'no',
                'choices': ['yes', 'no']
            },
        },
        required_if=[
            ["specific", "yes", ["name"]],
        ],
        supports_check_mode=True)

    pfcert = pfSenseCERTinfo(module)

    cert = dict()
    cert['descr'] = module.params['name']
    state = module.params['state']
    specific = module.params['specific']
    exact = module.params['exact']
    if state == 'absent':
        pfcert.remove(cert)
    elif state == 'present' and specific == 'no':
        pfcert.return_listall(cert)
    elif state == 'present' and specific == 'yes' and exact == 'yes':
        pfcert._list_cert(cert['descr'])
    elif state == 'present' and specific == 'yes' and exact == 'no':
        pfcert._list_cert_match(cert['descr'])

if __name__ == '__main__':
    main()
