#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '2.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsensible.core.cert
version_added: "2.10"
short_description: Manage ckSense Certificate
description:
  >
    Manage ckSense Certificate
author: CK Lee (@cklee288)
notes:
options:
  name:
    description: The name of the Certificate
    required: true
    type: str
  state:
    description: State in which to leave the Certificate
    required: true
    choices: [ "present", "absent" ]
    type: str
  certificate:
    description:
      >
        The certificate for the Certificate.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how ckSense stores it).
    type: str
  prv:
    description:
      >
        The private key for the Certificate.  This can be in PEM
        form or Base64 encoded PEM as a single string (which is how ckSense stores it).
    type: str
"""

EXAMPLES = """
- name: Add AD Certificate
  pfsensible.core.cert:
    name: AD CERT
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dB...
    prv: |
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEaXkz6XajhEv7
      ...
      ylZPVxnaNddPAd0cqhvp7zE=
      -----END PRIVATE KEY-----
    state: present

- name: Remove AD Certificate
  pfsensible.core.cert:
    name: AD CERT
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule


class pfSenseCERT(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = PFSenseModule(module)
        self.certs = self.pfsense.get_elements('cert')

    def _find_cert(self, name):
        found = None
        i = 0
        for cert in self.certs:
            i = self.pfsense.get_index(cert)
            if cert.find('descr').text == name:
                found = cert
                break
        return (found, i)



    def validate_cert(self, cert):
        lines = cert.splitlines()
        if lines[0] == '-----BEGIN CERTIFICATE-----' and lines[-1] == '-----END CERTIFICATE-----':
            return base64.b64encode(cert)
        elif re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', cert):
            return cert
        else:
            self.module.fail_json(msg='Could not recognize certificate format: %s' % (cert))

    def validate_prv(self, prv):
        lines = prv.splitlines()
        if lines[0] == '-----BEGIN PRIVATE KEY-----' and lines[-1] == '-----END PRIVATE KEY-----':
            return base64.b64encode(prv)
        elif lines[0] == '-----BEGIN RSA PRIVATE KEY----' and lines[-1] == '-----END RSA PRIVATE KEY-----':
            return base64.b64encode(prv)
        elif re.match('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t', prv):
            return prv
        elif re.match('LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0t', prv):
            return prv
        else:
            self.module.fail_json(msg='Could not recognize private key format: %s' % (prv))



    def add(self, cert):
        cert_elt, cert_idx = self._find_cert(cert['descr'])
        changed = False
        diff = {}
        stdout = None
        stderr = None
        if cert_elt is None:
            diff['before'] = ''
            changed = True
            cert_elt = self.pfsense.new_element('cert')
            cert['refid'] = self.pfsense.uniqid()
            self.pfsense.copy_dict_to_element(cert, cert_elt)
            self.pfsense.root.append(cert_elt)
            descr = 'ansible pfsensible.core.cert added %s' % (cert['descr'])
        else:
            diff['before'] = self.pfsense.element_to_dict(cert_elt)
            if self.pfsense.copy_dict_to_element(cert, cert_elt):
                changed = True
            descr = 'ansible pfsensible.core.cert updated "%s"' % (cert['descr'])
        if changed and not self.module.check_mode:
            self.pfsense.write_config(descr=descr)
            # cert_import will base64 encode the cert + key  and will fix 'certref' for CERTs that reference each other
            # $cert needs to be an existing reference (particularly 'refid' must be set) before calling cert_import
            # key and serial are optional arguments.  TODO - handle key and serial
            (dummy, stdout, stderr) = self.pfsense.phpshell("""
                init_config_arr(array('cert'));
                $cert =& lookup_cert('{refid}');
                cert_import($cert, '{cert}','{priv}');
                print_r($cert);
                print_r($config['cert']);
                write_config();""".format(refid=cert_elt.find('refid').text, cert=base64.b64decode(cert_elt.find('crt').text), priv=base64.b64decode(cert_elt.find('prv').text)))
        diff['after'] = self.pfsense.element_to_dict(cert_elt)
        self.module.exit_json(changed=changed, diff=diff, stdout=stdout, stderr=stderr)

    def remove(self, cert):
        cert_elt, dummy = self._find_cert(cert['descr'])
        changed = False
        diff = {}
        diff['after'] = {}
        if cert_elt is not None:
            changed = True
            diff['before'] = self.pfsense.element_to_dict(cert_elt)
            self.certs.remove(cert_elt)
        else:
            diff['before'] = {}
        if changed and not self.module.check_mode:
            self.pfsense.write_config(descr='ansible pfsensible.core.cert removed "%s"' % (cert['descr']))
        self.module.exit_json(changed=changed, diff=diff)


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'state': {
                'required': True,
                'choices': ['present', 'absent']
            },
            'certificate': {'required': False, 'type': 'str'},
            'prv': {'required': False, 'type': 'str'},
        },
        required_if=[
            ["state", "present", ["certificate","prv"]],
        ],
        supports_check_mode=True)

    pfcert = pfSenseCERT(module)

    cert = dict()
    cert['descr'] = module.params['name']
    state = module.params['state']
    if state == 'absent':
        pfcert.remove(cert)
    elif state == 'present':
        cert['crt'] = pfcert.validate_cert(module.params['certificate'])
        cert['prv'] = pfcert.validate_prv(module.params['prv'])
        pfcert.add(cert)


if __name__ == '__main__':
    main()
