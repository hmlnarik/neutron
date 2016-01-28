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
from copy import copy

from neutron.common import constants
from neutron.db.securitygroups_db import IP_PROTOCOL_MAP
from neutron.db.securitygroups_db import SecurityGroupRule
from neutron.debug import diagnostic_steps_secgroups as dss
from neutron.tests import base

import testtools.assertions as a
import testtools.matchers as m

TESTED_HOST_IPV6_FULL_NETWORK = "::/0"
TESTED_HOST_IPV6_WIDE_NETWORK = "2001:db8::/32"
TESTED_HOST_IPV6_NETWORK = "2001:db8::/64"
TESTED_HOST_IPV6_OTHER_NETWORK = "2001:db7::/64"
TESTED_HOST_IPV6_ADDRESS = "2001:db8::3602:12ff:2379:4392"

TESTED_HOST_IPV4_FULL_NETWORK = "0.0.0.0/0"
TESTED_HOST_IPV4_WIDE_NETWORK = "10.0.0.0/8"
TESTED_HOST_IPV4_NETWORK = "10.0.3.0/24"
TESTED_HOST_IPV4_OTHER_NETWORK = "10.0.0.0/24"
TESTED_HOST_IPV4_ADDRESS = "10.0.3.6"

SECURITY_GROUP_1 = "security-group-1"
SECURITY_GROUP_2 = "security-group-2"

RULE_IPV4_ANY = SecurityGroupRule(ethertype=constants.IPv4)
RULE_IPV6_ANY = SecurityGroupRule(ethertype=constants.IPv6)

RULE_IPV4_INGRESS = SecurityGroupRule(ethertype=constants.IPv4,
                                      direction="ingress")
RULE_IPV4_EGRESS = SecurityGroupRule(ethertype=constants.IPv4,
                                     direction="egress")
RULE_IPV6_INGRESS = SecurityGroupRule(ethertype=constants.IPv6,
                                      direction="ingress")
RULE_IPV6_EGRESS = SecurityGroupRule(ethertype=constants.IPv6,
                                     direction="egress")

TESTED_RULE_IPV4_TCP_SSH = SecurityGroupRule(
    ethertype=constants.IPv4, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
    remote_ip_prefix=TESTED_HOST_IPV4_ADDRESS)
TESTED_RULE_IPV4_TCP_SSH_SEC_GROUP = SecurityGroupRule(
    ethertype=constants.IPv4, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
    remote_group_id=SECURITY_GROUP_1)
TESTED_RULE_IPV6_TCP_SSH = SecurityGroupRule(
    ethertype=constants.IPv6, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
    remote_ip_prefix=TESTED_HOST_IPV6_ADDRESS)
TESTED_RULE_IPV6_TCP_SSH_SEC_GROUP = SecurityGroupRule(
    ethertype=constants.IPv6, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
    remote_group_id=SECURITY_GROUP_1)

OTHER_RULE_IPV4_TCP_SSH = SecurityGroupRule(
    ethertype=constants.IPv4, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
    remote_ip_prefix=TESTED_HOST_IPV4_OTHER_NETWORK)
OTHER_RULE_IPV6_TCP_SSH = SecurityGroupRule(
    ethertype=constants.IPv6, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
    remote_ip_prefix=TESTED_HOST_IPV6_OTHER_NETWORK)

TESTED_RULE_IPV4_UDP_SSH = SecurityGroupRule(
    ethertype=constants.IPv4, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_UDP),
    remote_ip_prefix=TESTED_HOST_IPV4_ADDRESS)
TESTED_RULE_IPV6_UDP_SSH = SecurityGroupRule(
    ethertype=constants.IPv6, port_range_min=22, port_range_max=22,
    protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_UDP),
    remote_ip_prefix=TESTED_HOST_IPV6_ADDRESS)


class TestSecurityRuleEnclosing(base.BaseTestCase):
    def assert_port_range_covered(self, sample_rule):
        def test_range(expected, min, max):
            covering_rule = copy(sample_rule)
            covering_rule['port_range_min'] = min
            covering_rule['port_range_max'] = max
            a.assert_that(
                dss.security_rule_embodies(tested_rule, covering_rule),
                m.Equals(expected),
                "Rule should be covered for port range (%s, %s)" %
                (min, max))

        tested_rule = copy(sample_rule)
        tested_rule['port_range_min'] = 22
        tested_rule['port_range_max'] = 25

        test_range(True, 22, 25)
        test_range(True, 22, 123)
        test_range(True, 1, 25)
        test_range(True, None, 25)
        test_range(True, 22, None)
        test_range(True, None, None)

        test_range(False, 1, 2)
        test_range(False, 23, 24)
        test_range(False, 45, 123)
        test_range(False, None, 21)
        test_range(False, None, 24)
        test_range(False, 25, None)
        test_range(False, 23, None)
        test_range(False, "b", "a")

    def test_ssh_tcp_port(self):
        self.assert_port_range_covered(TESTED_RULE_IPV4_TCP_SSH)
        self.assert_port_range_covered(TESTED_RULE_IPV6_TCP_SSH)

    def test_ingress_egress(self):
        self.assertFalse(
            dss.security_rule_embodies(RULE_IPV4_INGRESS, RULE_IPV4_EGRESS))
        self.assertFalse(
            dss.security_rule_embodies(RULE_IPV6_INGRESS, RULE_IPV6_EGRESS))

        self.assertFalse(
            dss.security_rule_embodies(RULE_IPV4_EGRESS, RULE_IPV4_INGRESS))
        self.assertFalse(
            dss.security_rule_embodies(RULE_IPV6_EGRESS, RULE_IPV6_INGRESS))

    def test_networks_CIDR(self):
        def test_cidr(expected, new_cidr):
            covering_rule = copy(tested_rule)
            covering_rule.remote_ip_prefix = new_cidr

            a.assert_that(
                dss.security_rule_embodies(tested_rule, covering_rule),
                m.Equals(expected),
                "CIDR %s should %sbe covered by rule for CIDR %s" %
                (tested_rule.remote_ip_prefix,
                 "" if expected else "not ",
                 covering_rule.remote_ip_prefix))

        tested_rule = TESTED_RULE_IPV4_TCP_SSH

        test_cidr(True, TESTED_HOST_IPV4_FULL_NETWORK)
        test_cidr(True, TESTED_HOST_IPV4_WIDE_NETWORK)
        test_cidr(True, TESTED_HOST_IPV4_NETWORK)
        test_cidr(False, TESTED_HOST_IPV4_OTHER_NETWORK)

        tested_rule = TESTED_RULE_IPV6_TCP_SSH

        test_cidr(True, TESTED_HOST_IPV6_FULL_NETWORK)
        test_cidr(True, TESTED_HOST_IPV6_WIDE_NETWORK)
        test_cidr(True, TESTED_HOST_IPV6_NETWORK)
        test_cidr(False, TESTED_HOST_IPV6_OTHER_NETWORK)

    def test_networks_secgroups(self):
        def test_secgroup(expected, new_secgroup):
            covering_rule = copy(tested_rule)
            covering_rule.remote_group_id = new_secgroup

            a.assert_that(
                dss.security_rule_embodies(tested_rule, covering_rule),
                m.Equals(expected),
                "Security group %s should %sbe covered by rule for "
                "security group %s" %
                (tested_rule.remote_group_id,
                 "" if expected else "not ",
                 covering_rule.remote_group_id))

        tested_rule = TESTED_RULE_IPV4_TCP_SSH_SEC_GROUP

        test_secgroup(True, SECURITY_GROUP_1)
        test_secgroup(False, SECURITY_GROUP_2)

        tested_rule = TESTED_RULE_IPV6_TCP_SSH_SEC_GROUP

        test_secgroup(True, SECURITY_GROUP_1)
        test_secgroup(False, SECURITY_GROUP_2)
