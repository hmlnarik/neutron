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

from neutron._i18n import _
from neutron.agent.l3 import namespaces
from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.debug import diagnostic_steps_base as dsb


def router_ns(router_id):
    return namespaces.build_ns_name(namespaces.NS_PREFIX, router_id)


def dhcp_ns(network_id):
    return namespaces.build_ns_name(dhcp.NS_PREFIX, network_id)


class CheckRouterNamespaceExistenceStep(dsb.DiagnosticStep):
    def __init__(self, router_id):
        dsb.DiagnosticStep.__init__(self,
                                    _('Check existence of router namespace'))
        self.router_id = router_id

    def diagnose(self, debug_agent, state):
        root_ip = ip_lib.IPWrapper()
        ns = router_ns(self.router_id)
        result = root_ip.netns.exists(ns)

        return self.create_result_info(result)


class CheckNetworkNamespaceExistenceStep(dsb.DiagnosticStep):
    def __init__(self, network_id):
        dsb.DiagnosticStep.__init__(self,
                                    _('Check existence of network namespace'))
        self.network_id = network_id

    def diagnose(self, debug_agent, state):
        root_ip = ip_lib.IPWrapper()
        ns = dhcp_ns(self.network_id)
        result = root_ip.netns.exists(ns)

        return self.create_result_info(result)
