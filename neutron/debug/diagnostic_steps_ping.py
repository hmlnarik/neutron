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
from neutron.debug import diagnostic_steps_base as ds
from neutron.debug import diagnostic_steps_ns as ds_ns

LOG = logging.getLogger(__name__)


class PingFromNamespaceStep(ds.ExecCmdWithIpFromNamespaceStep):
    def __init__(self, timeout=1, **kwargs):
        ds.ExecCmdWithIpFromNamespaceStep.__init__(self, **kwargs)
        self.timeout = timeout

    def get_command(self, state):
        if self.target_ip_addr.version == 4:
            ping_command_template = c.PING_IPV4
        elif self.target_ip_addr.version == 6:
            ping_command_template = c.PING_IPV6

        ping_command = ping_command_template % {
            'timeout': self.timeout,
            'destination': self.target_ip_addr
        }

        return ping_command

    def clone_for_ip_address(self, new_ip_address):
        return PingFromNamespaceStep(name=self.get_name(),
                                     namespace=self.namespace,
                                     target_ip_addr=new_ip_address,
                                     timeout=self.timeout)


class PingFromRouterNamespaceStep(PingFromNamespaceStep):
    def __init__(self, router_id=None, **kwargs):
        PingFromNamespaceStep.__init__(
            self,
            name=_('Ping from router namespace'),
            namespace=ds_ns.router_ns(router_id),
            **kwargs)


class PingFromDhcpNamespaceStep(PingFromNamespaceStep):
    def __init__(self, network_id=None, **kwargs):
        PingFromNamespaceStep.__init__(
            self,
            name=_('Ping from network namespace'),
            namespace=ds_ns.dhcp_ns(network_id),
            **kwargs)
        self.network_id = network_id

    def create_result_info(self, step_result, message=None):
        message = (
            _("Network id: %s") % self.network_id
            ("\n" + message) if message else ""
        )

        return super(PingFromDhcpNamespaceStep, self).create_result_info(
            step_result, message=message)
