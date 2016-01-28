# Copyright 2016 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License,  Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,  software
#    distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND,  either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging

from neutron._i18n import _

from neutron.debug import constants as c
from neutron.debug import diagnostic_steps_base as dsb
from neutron.debug import diagnostic_steps_ns as ds_ns
from neutron.debug import diagnostic_steps_secgroups as dss
from neutron.debug import exceptions as exc


LOG = logging.getLogger(__name__)


class CheckPortsAdminStateUpStep(dsb.DiagnosticStep):
    name = _('Check admin state of ports')

    def __init__(self, get_ports_func=None, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)
        self.get_ports_func = get_ports_func

    def diagnose(self, debug_agent, state):
        ports = self.get_ports_func(state)
        if not ports:
            err = _('Ports have to be obtained first')
            return self.create_result_info(False,
                                           message=err)

        admin_disabled_ports = [port['id'] for port in ports
                                if not port.get('admin_state_up', None)]

        if admin_disabled_ports:
            msg = _("Disabled ports: %s") % admin_disabled_ports
            return self.create_result_info(False, message=msg)
        else:
            return self.create_result_info(True)


class CheckRouterAdminStateUpStep(dsb.DiagnosticStep):
    name = _('Check admin state of router')

    def __init__(self, router_id=None, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)
        self.router_id = router_id

    def diagnose(self, debug_agent, state):
        router_info = debug_agent.get_router(self.router_id)
        if not router_info.get('admin_state_up', False):
            return self.create_result_info(False, _("Router is disabled"))
        else:
            return self.create_result_info(True)


class CheckTcpPortOpenFromNsStep(dsb.ExecCmdWithIpFromNamespaceStep):
    def __init__(self, timeout=1, port_number=22, **kwargs):
        dsb.ExecCmdWithIpFromNamespaceStep.__init__(self, **kwargs)
        self.timeout = timeout
        self.port_number = port_number

    def get_command(self, state):
        if self.target_ip_addr.version == 4:
            test_command_template = c.TEST_TCP_OPEN_IPV4
        elif self.target_ip_addr.version == 6:
            test_command_template = c.TEST_TCP_OPEN_IPV6

        test_command = test_command_template % {
            'timeout': self.timeout,
            'destination': self.target_ip_addr,
            'port': self.port_number
        }

        return test_command

    def get_result_message_header(self):
        return _("IP: %(ip)s, TCP port: %(port)s, NS: %(ns)s") % {
            'ip': self.target_ip_addr,
            'ns': self.namespace,
            'port': self.port_number
        }

    def clone_for_ip_address(self, new_ip_address):
        return CheckTcpPortOpenFromNsStep(name=self.get_name(),
                                          namespace=self.namespace,
                                          target_ip_addr=new_ip_address,
                                          timeout=self.timeout,
                                          port_number=self.port_number)

    def diagnose(self, debug_agent, state):
        res = super(CheckTcpPortOpenFromNsStep, self).diagnose(debug_agent,
                                                               state)

        if not res.get_result():
            port = state.get_port_from_ip_address(self.target_ip_addr)
            port_sgs = port.get('security_groups', [])

            res.add_next_step(
                dss.step_check_tcp_sec_rule(port_sgs,
                                            tcp_port_min=self.port_number,
                                            tcp_port_max=self.port_number,
                                            ip_addr=self.target_ip_addr))

        return res


class CheckTcpPortOpenFromRouterNamespaceStep(CheckTcpPortOpenFromNsStep):
    name = _('Check TCP port open from router namespace')

    def __init__(self, router_id=None, **kwargs):
        CheckTcpPortOpenFromNsStep.__init__(
            self,
            namespace=ds_ns.router_ns(router_id),
            **kwargs
        )


class ObtainRouterPortsAndNetworksStep(dsb.DiagnosticStep):
    """
    Obtains ports of the given routers, and gathers networks of
    the obtained ports into state[KEY_ROUTER_NETWORK_IDS][router_id]
    """

    name = _('Obtain router ports and networks')

    def __init__(self, router_id=None, get_ports_func=None, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)
        if get_ports_func:
            self.get_ports_func = get_ports_func
        elif router_id is not None:
            self.get_ports_func = lambda state: router_id
        else:
            raise exc.InvalidArgumentError(reason=_('Either router_id or '
                                                    'get_ports_func must be '
                                                    'given'))

    def diagnose(self, debug_agent, state):
        routers = self.get_ports_func(state)
        if type(routers) in [list, set, tuple]:
            res = [self._retrieve_network_ports(debug_agent, state, r_id)
                   for r_id in routers]
        elif routers is not None:
            res = self._retrieve_router_ports(debug_agent, state, routers)
        else:
            res = None

        return res

    def _retrieve_router_ports(self, debug_agent, state, router_id):
        result = state.get_router_ports(router_id)

        if not result:
            result = debug_agent.get_device_ports(device_id=router_id)
            state.add_router_ports(router_id, *result)

            networks = set([port['network_id'] for port in result])

            state.setdefault(c.STATE_ITEM_ROUTER_NETWORK_IDS, {})
            state[c.STATE_ITEM_ROUTER_NETWORK_IDS].setdefault(router_id, set())
            state[c.STATE_ITEM_ROUTER_NETWORK_IDS][router_id] |= networks

        msg = _('Router %(router_id)s: %(nets)d networks, %(ports)d ports') % {
            'router_id': router_id,
            'ports': len(result),
            'nets': len(state[c.STATE_ITEM_ROUTER_NETWORK_IDS][router_id])
        }

        return self.create_result_info(True, msg)


class ObtainNetworkPortsStep(dsb.DiagnosticStep):
    name = _('Obtain network ports')

    def __init__(self, network_id=None, get_ports_func=None, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)
        if get_ports_func:
            self.get_ports_func = get_ports_func
        elif network_id is not None:
            self.get_ports_func = lambda state: network_id
        else:
            raise exc.InvalidArgumentError(reason=_('Either network_id or '
                                                    'get_ports_func must be '
                                                    'given'))

    def diagnose(self, debug_agent, state):
        networks = self.get_ports_func(state)
        if type(networks) in [list, set, tuple]:
            res = [self._retrieve_network_ports(debug_agent, state, n_id)
                   for n_id in networks]
        elif networks is not None:
            res = self._retrieve_network_ports(debug_agent, state, networks)
        else:
            res = None

        return res

    def _retrieve_network_ports(self, debug_agent, state, network_id):
        result = state.get_network_ports(network_id)

        if not result:
            result = debug_agent.get_network_ports(network_id=network_id)
            state.add_network_ports(network_id, *result)

        msg = _('Network %(network_id)s: %(ports)d ports') % {
            'network_id': network_id,
            'ports': len(result)
        }

        return self.create_result_info(True, msg)


class ObtainFloatingToFixedIpStep(dsb.DiagnosticStep):
    """Obtains information on floating IPs from server and stores
    this data to state.

    Requires in state:
        nothing

    """

    name = _('Obtain floating to fixed IP map')

    def __init__(self, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)

    def diagnose(self, debug_agent, state):
        for f in debug_agent.get_floating_ips():
            state.add_floating_to_fixed_ip(f['floating_ip_address'],
                                           f['fixed_ip_address'],
                                           f.get('port_id', None))

        return self.create_result_info(True, state.get_floating_ips())
