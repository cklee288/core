# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lee Chee Kean (cklee28@gmail.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible.module_utils.compat.ipaddress import ip_address, ip_network

FRR_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    enable=dict(default='', required=False, choices=['on', '']),
    password=dict(required=False, type='str'),
    carpstatusvid=dict(default='none', required=False, type='str'),
    logging=dict(default='', required=False, choices=['on', '']),
    ignoreipsecrestart=dict(default='', required=False, choices=['on', '']),
    routerid=dict(required=False, type='str'),
    routevalue1=dict(required=False, type='str'),
    routetarget1=dict(required=False, type='str'),
    routevalue2=dict(required=False, type='str'),
    routetarget2=dict(required=False, type='str'),
    routevalue3=dict(required=False, type='str'),
    routetarget3=dict(required=False, type='str'),
    routevalue4=dict(required=False, type='str'),
    routetarget4=dict(required=False, type='str'),
    routevalue5=dict(required=False, type='str'),
    routetarget5=dict(required=False, type='str'),
    routevalue6=dict(required=False, type='str'),
    routetarget6=dict(required=False, type='str'),
    routevalue7=dict(required=False, type='str'),
    routetarget7=dict(required=False, type='str'),
    routevalue8=dict(required=False, type='str'),
    routetarget8=dict(required=False, type='str'),
    routevalue9=dict(required=False, type='str'),
    routetarget9=dict(required=False, type='str'),
    routevalue10=dict(required=False, type='str'),
    routetarget10=dict(required=False, type='str'),
    routevalue11=dict(required=False, type='str'),
    routetarget11=dict(required=False, type='str'),
    routevalue12=dict(required=False, type='str'),
    routetarget12=dict(required=False, type='str'),
    routevalue13=dict(required=False, type='str'),
    routetarget13=dict(required=False, type='str'),
    routevalue14=dict(required=False, type='str'),
    routetarget14=dict(required=False, type='str'),
    routevalue15=dict(required=False, type='str'),
    routetarget15=dict(required=False, type='str'),
    routevalue16=dict(required=False, type='str'),
    routetarget16=dict(required=False, type='str'),
    routevalue17=dict(required=False, type='str'),
    routetarget17=dict(required=False, type='str'),
    routevalue18=dict(required=False, type='str'),
    routetarget18=dict(required=False, type='str'),
    routevalue19=dict(required=False, type='str'),
    routetarget19=dict(required=False, type='str'),
    routevalue20=dict(required=False, type='str'),
    routetarget20=dict(required=False, type='str'),
)

FRR_REQUIRED_IF = [
    ["state", "present", ["password"]],
]


class PFSenseFrrModule(PFSenseModuleBase):
    """ module managing pfsense Frr """

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseFrrModule, self).__init__(module, pfsense)
        self.name = "pfsensible.core.Frr"
        self.root_elt = self.pfsense.get_element('installedpackages')
        self.obj = dict()
        self.interface_elt = None
        self.dynamic = False
        self.target_elt = None

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('installedpackages')
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

    def _check_subnet(self):
        """ check if addr lies into interface subnets """
        def _check_vips():
            virtualips = self.pfsense.get_element('virtualip')
            if virtualips is None:
                return False

            for vip_elt in virtualips:
                if vip_elt.find('interface').text != self.interface_elt.tag or vip_elt.find('mode').text != 'other' or vip_elt.find('type').text != 'network':
                    continue

                subnet = ip_network(u'{0}/{1}'.format(vip_elt.find('subnet').text, vip_elt.find('subnet_bits').text), strict=False)
                if addr in subnet:
                    return True
            return False

        if self.params['ipprotocol'] == 'inet':
            inet_type = 'IPv4'
            f1_elt = self.interface_elt.find('ipaddr')
            f2_elt = self.interface_elt.find('subnet')
        else:
            inet_type = 'IPv6'
            f1_elt = self.interface_elt.find('ipaddrv6')
            f2_elt = self.interface_elt.find('subnetv6')
        if f1_elt is None or f1_elt.text is None or f2_elt is None or f2_elt.text is None:
            self.module.fail_json(msg='Cannot add {0} Gateway Address because no {0} address could be found on the interface.'.format(inet_type))

        try:
            if self.params['nonlocalgateway']:
                return

            addr = ip_address(u'{0}'.format(self.params['gateway']))
            subnet = ip_network(u'{0}/{1}'.format(f1_elt.text, f2_elt.text), strict=False)
            if addr in subnet or _check_vips():
                return

            self.module.fail_json(msg="The gateway address {0} does not lie within one of the chosen interface's subnets.".format(self.params['gateway']))
        except ValueError:
            self.module.fail_json(msg='Cannot add {0} Gateway Address because no {0} address could be found on the interface.'.format(inet_type))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        mainobj = dict()
        obj = dict()
        # obj['name'] = params['name']
        if params['state'] == 'present':
            # self._get_interface(params['interface'], obj)
            self._get_ansible_param(obj, 'enable')
            self._get_ansible_param(obj, 'password')
            self._get_ansible_param(obj, 'carpstatusvid')
            self._get_ansible_param(obj, 'logging')
            self._get_ansible_param(obj, 'routerid')
            self._get_ansible_param(obj, 'ignoreipsecrestart')
            list = []
            subobj = dict()
            
            # routevalue and its routetarget#
            for i in range (1, 21): 

                if params.get('routevalue{}'.format(i)) is not None and (params['routevalue{}'.format(i)] != ''):
                    subobj['routevalue'] = params['routevalue{}'.format(i)]
                    rtitem = params['routetarget{}'.format(i)]
                    fields = rtitem.split('|')
                    # fields = rtitem.text.split('|')
                    interfacename = self._return_interface(fields[1])
                    subobj['routetarget'] = fields[0] + '|' + interfacename
                    list.append(dict(subobj))
            obj['row'] = list
            mainobj['config'] = obj

        else:
            obj['enable'] = ''
            mainobj['config'] = obj

        return mainobj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params


        self.target_elt = self.pfsense.find_frr_elt()
        # if self.target_elt is not None and self.target_elt.find('gateway').text == 'dynamic':
        #     self.dynamic = True

        if params['state'] == 'present':
            # check routerip
            if params.get('routerid') is not None and (params['routerid'] != ''):
                rid_ipaddrtype = ip_address(u'{0}'.format(self.params['routerid']))
                if not rid_ipaddrtype:
                    self.module.fail_json(msg='routerid must be IP address format xx.xx.xx.xx')

            # check routevalue#
            for i in range (1, 20): 
                # print("{:6d} {:6d} {:6d} {:6d}"
                # .format(i, i ** 2, i ** 3, i ** 4)) 
                if params.get('routevalue{}'.format(i)) is not None and (params['routevalue{}'.format(i)] != ''):
                    r_ipnetworktype = ip_network(u'{0}'.format(self.params['routevalue{}'.format(i)]))
                    if not r_ipnetworktype:
                        self.module.fail_json(msg='routevalue{} must be IP address format xx.xx.xx.xx/xx'.format(i))
                    if params.get('routetarget{}'.format(i)) is None or (params['routetarget{}'.format(i)] == ''):
                        self.module.fail_json(msg='routetarget{} must pointed to interface or gateway'.format(i))                   
                    else:
                        rtitem = params['routetarget{}'.format(i)]
                        fields = rtitem.split('|')
                        # fields = rtitem.text.split('|')
                        if fields and fields[0] == "gw":
                            gateway_elt = self.pfsense.find_gateway_elt(fields[1])
                            if gateway_elt is None:
                                self.module.fail_json(msg='%s is not a valid gateway' % (fields[1]))
                        elif fields and fields[0] == "if":
                            self._verify_interface(fields[1])
                            # if interface_verify is None:
                            #     self.module.fail_json(msg='%s is not a valid interface description' % (fields[1]))
                        else:
                            self.module.fail_json(msg='1st field (input %s) is not gw or if' % (fields[0]))

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('frr')

    def _find_target(self):
        """ find the XML target_elt """
        return self.pfsense.find_frr_elt()

    def _get_interface(self, name, obj):
        """ return pfsense interface by name """
        for interface in self.pfsense.interfaces:
            descr_elt = interface.find('descr')
            if descr_elt is not None and descr_elt.text.strip() == name:
                obj['interface'] = interface.tag
                self.interface_elt = interface
                return
        self.module.fail_json(msg='Interface {0} not found'.format(name))

    def _return_interface(self, name):
        """ return pfsense interface through descriptioname """
        for interface in self.pfsense.interfaces:
            descr_elt = interface.find('descr')
            if descr_elt is not None and descr_elt.text.strip() == name:
                return interface.tag
        self.module.fail_json(msg='Interface {0} not found'.format(name))


    def _verify_interface(self, name):
        """ verify pfsense interface by name """
        for interface in self.pfsense.interfaces:
            descr_elt = interface.find('descr')
            if descr_elt is not None and descr_elt.text.strip() == name:
                return
        self.module.fail_json(msg='Interface {0} not found'.format(name))

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return ['disabled', 'monitor', 'monitor_disable', 'action_disable', 'force_down', 'nonlocalgateway']

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell('''
require_once("filter.inc");
include('/usr/local/pkg/frr.inc');
frr_global_validate_input();
frr_generate_config();
frr_package_install();
$retval = 0;

$retval |= system_routing_configure();
$retval |= system_resolvconf_generate();
$retval |= filter_configure();
/* reconfigure our gateway monitor */
setup_gateways_monitor();

if ($retval == 0) clear_subsystem_dirty('staticroutes');
''')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format('frr')

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            # values += self.format_cli_field(self.params, 'interface')
            # values += self.format_cli_field(self.obj, 'ipprotocol', default='inet')
            # values += self.format_cli_field(self.obj, 'gateway')
            # values += self.format_cli_field(self.obj, 'descr', default='')
            # values += self.format_cli_field(self.params, 'disabled', fvalue=self.fvalue_bool, default=False)
            # values += self.format_cli_field(self.obj, 'monitor')
            # values += self.format_cli_field(self.params, 'monitor_disable', fvalue=self.fvalue_bool, default=False)
            # values += self.format_cli_field(self.params, 'action_disable', fvalue=self.fvalue_bool, default=False)
            # values += self.format_cli_field(self.params, 'force_down', fvalue=self.fvalue_bool, default=False)
            # values += self.format_cli_field(self.obj, 'weight', default='1')
            # values += self.format_cli_field(self.params, 'nonlocalgateway', fvalue=self.fvalue_bool, default=False)
            values = 'test frr create'

        else:
            # fbefore = dict()
            # fbefore['interface'] = self.pfsense.get_interface_display_name(before['interface'])

            # values += self.format_updated_cli_field(self.params, fbefore, 'interface', add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'ipprotocol', default='inet', add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'gateway', add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'descr', default='', add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'disabled', fvalue=self.fvalue_bool, default=False, add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'monitor', add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'monitor_disable', fvalue=self.fvalue_bool, default=False, add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'action_disable', fvalue=self.fvalue_bool, default=False, add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'force_down', fvalue=self.fvalue_bool, default=False, add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'weight', default='1', add_comma=(values))
            # values += self.format_updated_cli_field(self.obj, before, 'nonlocalgateway', fvalue=self.fvalue_bool)
              values = 'test frr replace'
        return values
