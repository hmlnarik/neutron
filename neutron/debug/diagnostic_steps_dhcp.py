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
from oslo_utils import importutils

from neutron._i18n import _
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.debug import diagnostic_steps_base as dsb


LOG = logging.getLogger(__name__)


def _get_dhcp_process_monitor(config):
    return external_process.ProcessMonitor(config=config,
                                           resource_type='dhcp')


class CheckDhcpAliveStep(dsb.DiagnosticStep):
    name = _('Check DHCP service running')

    class FakeDhcpPlugin(object):
        """Fake RPC plugin to bypass any RPC calls."""
        def __getattribute__(self, name):
            def fake_method(*args):
                pass
            return fake_method

    def __init__(self, get_network_ids=None, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)
        self.get_network_ids = get_network_ids

    def _is_dhcp_daemon_running(self, conf, network_id):
        dhcp_driver = importutils.import_object(
            conf.dhcp_driver,
            conf=conf,
            process_monitor=_get_dhcp_process_monitor(conf),
            network=dhcp.NetModel({'id': network_id}),
            plugin=CheckDhcpAliveStep.FakeDhcpPlugin())

        return dhcp_driver.active

    def diagnose(self, debug_agent, state):
        networks = self.get_network_ids(state)
        if not networks:
            err = _('No networks obtained')
            return self.create_result_info(True,
                                           message=err)

        dhcp_failed = [network_id for network_id in networks
                       if not self._is_dhcp_daemon_running(debug_agent.conf,
                                                           network_id)]

        if dhcp_failed:
            msg = _("DHCP daemon not running for networks: %s") % dhcp_failed
            return self.create_result_info(False, message=msg)
        else:
            return self.create_result_info(True)
