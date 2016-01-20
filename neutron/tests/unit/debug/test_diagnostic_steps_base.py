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

import socket

import mock
from oslo_config import cfg
import testtools.assertions as a
import testtools.matchers as m

from neutron.debug import diagnostic_steps_base as dsb
from neutron.extensions import portbindings
from neutron.tests import base

IPV4_ROUTER1_PORT1 = "10.0.3.3"
IPV6_ROUTER1_PORT1 = "2001:db8:1234:0:f816:3eff:fe4f:a233"
IPV6_ROUTER1_PORT1_ALT = "2001:db8:1234::f816:3eff:fe4f:a233"
IPV4_ROUTER2_PORT1 = "10.0.3.4"
IPV6_ROUTER2_PORT1 = "2001:db8:1234:0:f816:3eff:fe4f:a244"

TEST_ROUTER1_ID = '123-456-789'
TEST_ROUTER2_ID = '234-567-890'
OWNER1 = 'owner1'
OWNER2 = 'owner2'
FAKE_NETWORK1_ID = 'fake_net'
FAKE_NETWORK2_ID = 'fake_net_2'
FAKE_SUBNET1_ID = 'fake_subnet'
FAKE_SUBNET2_ID = 'fake_subnet_2'

FAKE_ROUTER1_PORT1 = {
    'device_owner': OWNER1,
    'admin_state_up': True,
    'network_id': FAKE_NETWORK1_ID,
    'tenant_id': 'fake_tenant',
    portbindings.HOST_ID: cfg.CONF.host,
    "fixed_ips": [
        {
            "ip_address": IPV4_ROUTER1_PORT1,
            "subnet_id": "811b26f4-8ab1-4dbb-a505-e2d59237dd35"
        },
        {
            "ip_address": IPV6_ROUTER1_PORT1,
            "subnet_id": "d9f1f2ea-e01e-46fc-93b9-0e901385014e"
        }
    ],
    'device_id': socket.gethostname()}

FAKE_ROUTER1_PORT2 = {
    'device_owner': OWNER2,
    'admin_state_up': True,
    'network_id': FAKE_NETWORK1_ID,
    'tenant_id': 'fake_tenant',
    portbindings.HOST_ID: cfg.CONF.host,
    'fixed_ips': [{'subnet_id': FAKE_SUBNET1_ID}],
    'device_id': socket.gethostname()}

FAKE_ROUTER2_PORT1 = {
    'device_owner': OWNER2,
    'admin_state_up': True,
    'network_id': FAKE_NETWORK1_ID,
    'tenant_id': 'fake_tenant',
    portbindings.HOST_ID: cfg.CONF.host,
    "fixed_ips": [
        {
            "ip_address": IPV4_ROUTER2_PORT1,
            "subnet_id": "811b26f4-8ab1-4dbb-a505-e2d59237dd35"
        },
        {
            "ip_address": IPV6_ROUTER2_PORT1,
            "subnet_id": "d9f1f2ea-e01e-46fc-93b9-0e901385014e"
        }
    ],
    'device_id': socket.gethostname()}


class TestDiagnosticStepState(base.BaseTestCase):
    def test_state_is_like_map(self):
        # Test that state provides simple key -> value support
        state = dsb.DiagnosticStepState(answer=42)
        state['blah'] = {'a': 'b'}

        a.assert_that(state, m.Contains('answer'))
        a.assert_that(state['answer'], m.Is(42))

        a.assert_that(state, m.Contains('blah'))
        a.assert_that(state['blah'], m.Contains('a'))
        a.assert_that(state['blah']['a'], m.Equals('b'))

    def test_add_router_port(self):
        state = dsb.DiagnosticStepState()

        state.add_router_ports(TEST_ROUTER1_ID, FAKE_ROUTER1_PORT1,
                               FAKE_ROUTER1_PORT2)
        state.add_router_ports(TEST_ROUTER2_ID, FAKE_ROUTER2_PORT1)

        a.assert_that(state.get_port_from_ip_address(IPV4_ROUTER1_PORT1),
                      m.Is(FAKE_ROUTER1_PORT1))
        a.assert_that(state.get_port_from_ip_address(IPV6_ROUTER1_PORT1),
                      m.Is(FAKE_ROUTER1_PORT1))
        a.assert_that(state.get_port_from_ip_address(IPV6_ROUTER1_PORT1_ALT),
                      m.Is(FAKE_ROUTER1_PORT1))
        a.assert_that(state.get_router_ports(TEST_ROUTER1_ID),
                      m.Equals([FAKE_ROUTER1_PORT1, FAKE_ROUTER1_PORT2]))
        a.assert_that(state.get_router_ports(TEST_ROUTER2_ID),
                      m.Equals([FAKE_ROUTER2_PORT1]))

    def test_add_network_port(self):
        state = dsb.DiagnosticStepState()

        state.add_network_ports(FAKE_NETWORK1_ID, FAKE_ROUTER1_PORT1,
                                FAKE_ROUTER1_PORT2)

        a.assert_that(state.get_port_from_ip_address(IPV4_ROUTER1_PORT1),
                      m.Is(FAKE_ROUTER1_PORT1))
        a.assert_that(state.get_port_from_ip_address(IPV6_ROUTER1_PORT1),
                      m.Is(FAKE_ROUTER1_PORT1))
        a.assert_that(state.get_network_ports(FAKE_NETWORK1_ID),
                      m.Equals([FAKE_ROUTER1_PORT1, FAKE_ROUTER1_PORT2]))


class TestExecCmdWithIpFromNamespaceStep(base.BaseTestCase):
    class TestCommand(dsb.ExecCmdWithIpFromNamespaceStep):
        def __init__(self, **kwargs):
            dsb.ExecCmdWithIpFromNamespaceStep.__init__(self,
                                                        "Test Command",
                                                        **kwargs)

        def clone_for_ip_address(self, new_ip_address):
            return TestExecCmdWithIpFromNamespaceStep.TestCommand(
                    target_ip_address=new_ip_address)

        def get_command(self, state):
            return '/bin/true'

    def test_diagnose_no_namespace(self):
        state = dsb.DiagnosticStepState()
        cmd = TestExecCmdWithIpFromNamespaceStep.TestCommand(
            target_ip_addr=IPV4_ROUTER1_PORT1,
            namespace="ns-123456789"
        )

        with mock.patch('neutron.agent.linux.ip_lib.IpNetnsCommand') as ns:
            agent = mock.Mock()
            result = cmd.diagnose(agent, state)

            ns.assert_has_calls([mock.call().execute(["/bin/true"],
                                                     log_fail_as_error=False,
                                                     run_as_root=True)])

        a.assert_that(result, m.IsInstance(dsb.DiagnosticStepResult))
