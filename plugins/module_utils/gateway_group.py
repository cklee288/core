### still working in progress

# -*- coding: utf-8 -*-


# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible.module_utils.compat.ipaddress import ip_address, ip_network

GATEWAYGROUP_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    description=dict(required=False, type='str'),
    name=dict(required=True, type='str'),
    gateway1=dict(required=False, type='str'),
    gateway2=dict(required=False, type='str'),
    gateway3=dict(required=False, type='str'),
    gateway4=dict(required=False, type='str'),
    gateway5=dict(required=False, type='str'),
    gateway_pr1=dict(required=False, choices=['1', '2', '3', '4', '5']),
    gateway_pr2=dict(required=False, choices=['1', '2', '3', '4', '5']),
    gateway_pr3=dict(required=False, choices=['1', '2', '3', '4', '5']),
    gateway_pr4=dict(required=False, choices=['1', '2', '3', '4', '5']),
    gateway_pr5=dict(required=False, choices=['1', '2', '3', '4', '5']),
    trigger=dict(required=False, choices=['down', 'downloss', 'downlatency', 'downlosslatency']),
)

GATEWAYGROUP_REQUIRED_IF = [
    ["state", "present", ["gateway_pr1", "gateway1", "trigger"]],
]


class PFSenseGatewaygroupModule(PFSenseModuleBase):
    """ module managing pfsense gateway groups """

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseGatewaygroupModule, self).__init__(module, pfsense)
        self.name = "pfsensible.core.gateway_group"
        self.root_elt = self.pfsense.get_element('gateways')
        self.obj = dict()
        self.interface_elt = None
        self.dynamic = False
        self.target_elt = None

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('gateways')
            self.pfsense.root.append(self.root_elt)

    ##############################
    # params processing
    #

    # def _check_gateway_groups(self):
    #     """ check if gateway is in use in gateway groups """
    #     for elt in self.root_elt:
    #         if (elt.tag == 'defaultgw4' or elt.tag == 'defaultgw6') and (elt.text is not None and elt.text == self.params['name']):
    #             return False

    #         if elt.tag != 'gateway_group':
    #             continue

    #         items = elt.findall('.//item')
    #         for item in items:
    #             fields = item.text.split('|')
    #             if fields and fields[0] == self.params['name']:
    #                 return False

    #     return True

    # def _check_routes(self):
    #     """ check if gateway is in use in static routes """
    #     routes = self.pfsense.get_element('staticroutes')
    #     if routes is None:
    #         return True

    #     for elt in routes:
    #         if elt.find('gateway').text == self.params['name']:
    #             return False

    #     return True

    def _check_rules(self):
        """ check if gatewaygroup is in use in filter rules """
        rules = self.pfsense.get_element('filter')
        if rules is None:
            return True

        for elt in rules:
            if elt.find('gateway').text == self.params['name']:
                return False

        return True

    def _check_ipsec(self):
        """ check if gatewaygroup is in use in ipsecs interface """
        ipsecs = self.pfsense.get_element('ipsec')
        if ipsecs is None:
            return True

        for elt in ipsecs:
            if elt.find('interface').text == self.params['name']:
                return False

        return True


    # def _check_subnet(self):
    #     """ check if addr lies into interface subnets """
    #     def _check_vips():
    #         virtualips = self.pfsense.get_element('virtualip')
    #         if virtualips is None:
    #             return False

    #         for vip_elt in virtualips:
    #             if vip_elt.find('interface').text != self.interface_elt.tag or vip_elt.find('mode').text != 'other' or vip_elt.find('type').text != 'network':
    #                 continue

    #             subnet = ip_network(u'{0}/{1}'.format(vip_elt.find('subnet').text, vip_elt.find('subnet_bits').text), strict=False)
    #             if addr in subnet:
    #                 return True
    #         return False

    #     if self.params['ipprotocol'] == 'inet':
    #         inet_type = 'IPv4'
    #         f1_elt = self.interface_elt.find('ipaddr')
    #         f2_elt = self.interface_elt.find('subnet')
    #     else:
    #         inet_type = 'IPv6'
    #         f1_elt = self.interface_elt.find('ipaddrv6')
    #         f2_elt = self.interface_elt.find('subnetv6')
    #     if f1_elt is None or f1_elt.text is None or f2_elt is None or f2_elt.text is None:
    #         self.module.fail_json(msg='Cannot add {0} Gateway Address because no {0} address could be found on the interface.'.format(inet_type))

    #     try:
    #         if self.params['nonlocalgateway']:
    #             return

    #         addr = ip_address(u'{0}'.format(self.params['gateway']))
    #         subnet = ip_network(u'{0}/{1}'.format(f1_elt.text, f2_elt.text), strict=False)
    #         if addr in subnet or _check_vips():
    #             return

    #         self.module.fail_json(msg="The gateway address {0} does not lie within one of the chosen interface's subnets.".format(self.params['gateway']))
    #     except ValueError:
    #         self.module.fail_json(msg='Cannot add {0} Gateway Address because no {0} address could be found on the interface.'.format(inet_type))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()

        obj['name'] = params['name']
        if params['state'] == 'present':
            # tempgwlists = [] (not required. let gateway1 tempgwlists declare list)
            self._get_ansible_param(obj, 'trigger')
            if 'gateway1' in params and params['gateway1'] is not None and params['gateway1'] != '':
                gateway1_elt = self.pfsense.find_gateway_elt(params['gateway1'])
                if gateway1_elt is None:
                    self.module.fail_json(msg='%s is not a valid gateway' % (params['gateway1']))
                elif 'gateway_pr1' in params and params['gateway_pr1'] is not None and params['gateway_pr1'] != '':
                    # obj['item'] = params['gateway1'] + '|' + params['gateway_pr1'] + '|' + 'address'
                    tempgwlists = [params['gateway1'] + '|' + params['gateway_pr1'] + '|' + 'address']
                else:
                    self.module.fail_json(msg='gateway1 priority has yet defined' )

            if 'description' in params and params['description'] is not None and params['description'] != '':
                obj['descr'] = params['description']
            else:
                obj['descr'] = ''

            if 'gateway2' in params and params['gateway2'] is not None and params['gateway2'] != '':
                gateway2_elt = self.pfsense.find_gateway_elt(params['gateway2'])
                if gateway2_elt is None:
                    self.module.fail_json(msg='%s is not a valid gateway' % (params['gateway2']))
                elif 'gateway_pr2' in params and params['gateway_pr2'] is not None and params['gateway_pr2'] != '':
                    gw_list2 = params['gateway2'] + '|' + params['gateway_pr2'] + '|' + 'address'
                    tempgwlists.append(gw_list2)
                else:
                    self.module.fail_json(msg='gateway2 defined but its priority has yet defined' )

            if 'gateway3' in params and params['gateway3'] is not None and params['gateway3'] != '':
                gateway3_elt = self.pfsense.find_gateway_elt(params['gateway3'])
                if gateway3_elt is None:
                    self.module.fail_json(msg='%s is not a valid gateway' % (params['gateway3']))
                elif 'gateway_pr3' in params and params['gateway_pr3'] is not None and params['gateway_pr3'] != '':
                    gw_list3 = params['gateway3'] + '|' + params['gateway_pr3'] + '|' + 'address'
                    tempgwlists.append(gw_list3)
                else:
                    self.module.fail_json(msg='gateway3 defined but its priority has yet defined' )

            if 'gateway4' in params and params['gateway4'] is not None and params['gateway4'] != '':
                gateway4_elt = self.pfsense.find_gateway_elt(params['gateway4'])
                if gateway4_elt is None:
                    self.module.fail_json(msg='%s is not a valid gateway' % (params['gateway4']))
                elif 'gateway_pr4' in params and params['gateway_pr4'] is not None and params['gateway_pr4'] != '':
                    gw_list4 = params['gateway4'] + '|' + params['gateway_pr4'] + '|' + 'address'
                    tempgwlists.append(gw_list4)
                else:
                    self.module.fail_json(msg='gateway4 defined but its priority has yet defined' )

            if 'gateway5' in params and params['gateway5'] is not None and params['gateway5'] != '':
                gateway5_elt = self.pfsense.find_gateway_elt(params['gateway5'])
                if gateway5_elt is None:
                    self.module.fail_json(msg='%s is not a valid gateway' % (params['gateway5']))
                elif 'gateway_pr5' in params and params['gateway_pr5'] is not None and params['gateway_pr5'] != '':
                    gw_list5 = params['gateway5'] + '|' + params['gateway_pr5'] + '|' + 'address'
                    tempgwlists.append(gw_list5)

                else:
                    self.module.fail_json(msg='gateway5 defined but its priority has yet defined' )

            obj['item'] = tempgwlists

        else:
           if not self._check_rules() or not self._check_ipsec():
                self.module.fail_json(msg="The gateway_group is still in use. You can not delete it")

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        # not required.

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('gateway_group')

    def _find_target(self):
        """ find the XML target_elt """
        # return self.pfsense.find_gateway_elt(self.obj['name'])
        return self.pfsense.find_gateway_group_elt(self.obj['name'])

    # def _get_interface(self, name, obj):
    #     """ return pfsense interface by name """
    #     for interface in self.pfsense.interfaces:
    #         descr_elt = interface.find('descr')
    #         if descr_elt is not None and descr_elt.text.strip() == name:
    #             obj['interface'] = interface.tag
    #             self.interface_elt = interface
    #             return
    #     self.module.fail_json(msg='Interface {0} not found'.format(name))

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return []

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell('''
require_once("filter.inc");
$retval = 0;

$retval |= system_routing_configure();
$retval |= system_resolvconf_generate();
$retval |= filter_configure();
/* reconfigure our gateway monitor */
setup_gateways_monitor();
/* Dynamic DNS on gw groups may have changed */
send_event("service reload dyndnsall");

if ($retval == 0) clear_subsystem_dirty('staticroutes');
''')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj['name'])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'item')
            values += self.format_cli_field(self.obj, 'descr', default='')
            values += self.format_cli_field(self.obj, 'trigger')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'item', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'descr', default='', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'trigger', add_comma=(values))
        return values
