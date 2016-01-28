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

import ipaddress as ipaddr

from oslo_log import log as logging

from neutron._i18n import _
from neutron.common import constants
from neutron.db.securitygroups_db import IP_PROTOCOL_MAP
from neutron.db.securitygroups_db import SecurityGroupRule
from neutron.debug import constants as c
from neutron.debug import diagnostic_steps_base as dsb


LOG = logging.getLogger(__name__)


def security_rule_embodies(tested_sec_rule, expected_enclosing_sec_rule):
    """
    Check whether the expected_enclosing_sec_rule embodies the (potentially
    partially) specified tested_sec_rule, i.e. if the
    expected_enclosing_sec_rule would allow traffic, then the tested_sec_rule
    would do as well.

    :param tested_sec_rule: Tested rule - dict with the attributes
        direction, ethertype, protocol, port_range_min, port_range_max,
        remote_group_id, remote_ip_prefix. The meaning of these attributes
        is the same as meaning of the corresponding attributes in
        neutron.db.securitygroups_db.SecurityGroupRule class. Missing
        attributes (except for remote_group_id and remote_ip_prefix)
        are not tested and do not contribute to the final decision.
    :param expected_enclosing_sec_rule: Rule with the same structure
        as tested_sec_rule.
    :return: Boolean value, True when expected_enclosing_sec_rule
        is applicable whenever tested_sec_rule would be
    """

    def check_eq(name):
        # Either the value is specified in the tested rule, and then it must
        # match the expected one, or it is not, and then no match is tested.
        # This does not work e.g. for security groups vs CIDR matching - if
        # the security group is present in the expected rule, then it must be
        # present in tested rule as well; hence security groups are
        # tested differently via check_strict_eq
        value = tested_sec_rule.get(name)
        if value is None:
            return None

        exp_value = expected_enclosing_sec_rule.get(name)
        return exp_value is not None and value == exp_value

    def check_strict_eq(name):
        # If the attribute is present in the expected rule, then it must be
        # present in tested rule as well. This is case of security groups.
        value = tested_sec_rule.get(name)
        exp_value = expected_enclosing_sec_rule.get(name)

        return (value is None and exp_value is None) or value == exp_value

    def check_in_range(name_min, name_max):
        value_min = tested_sec_rule.get(name_min)
        value_max = tested_sec_rule.get(name_max)

        exp_value_min = expected_enclosing_sec_rule.get(name_min)
        exp_value_max = expected_enclosing_sec_rule.get(name_max)

        return (exp_value_min is None or (
            value_min is not None and value_min >= exp_value_min
        )) and (exp_value_max is None or (
            value_max is not None and value_max <= exp_value_max
        ))

    def check_ip_addr_contained(name):
        value = tested_sec_rule.get(name)
        exp_value = expected_enclosing_sec_rule.get(name)

        if value is None and exp_value is None:
            return True
        if value is not None and exp_value is None:
            return False
        if value is None and exp_value is not None:
            return False

        ip_value = ipaddr.ip_interface(unicode(value))
        exp_ip_value = ipaddr.ip_interface(unicode(exp_value))

        return ip_value.network.subnet_of(exp_ip_value.network)

    if tested_sec_rule is None:
        # Any rule but undefined can cover empty (or not given) rule
        return expected_enclosing_sec_rule is not None

    tests = [
        check_eq('direction'),
        check_eq('ethertype'),
        check_eq('protocol'),
        check_strict_eq('remote_group_id'),
        check_ip_addr_contained('remote_ip_prefix')
    ]

    proto = expected_enclosing_sec_rule.get('protocol', None)
    if proto in [constants.PROTO_NUM_ICMP_V6, constants.PROTO_NUM_ICMP]:
        tests.append(check_strict_eq('port_range_min'))
        tests.append(check_strict_eq('port_range_max'))
    elif proto in [constants.PROTO_NUM_TCP, constants.PROTO_NUM_UDP]:
        tests.append(check_in_range('port_range_min', 'port_range_max'))

    # Note that there might be None values in the "tests" array, simple
    # condition joined using "and" would not work. Hence using test for
    # membership of False in the array.
    return False not in tests


def step_check_tcp_sec_rule(security_groups,
                            tcp_port_min,
                            tcp_port_max,
                            ip_addr=None,
                            ):
    et = constants.IPv4 if ip_addr.version == 4 else constants.IPv6
    rule = SecurityGroupRule(
        ethertype=et,
        port_range_min=tcp_port_min,
        port_range_max=tcp_port_max,
        protocol=IP_PROTOCOL_MAP.get(constants.PROTO_NAME_TCP),
        remote_ip_prefix=ip_addr
    )

    return CheckSecGroupRulePresentStep(
        rule=rule,
        get_security_group_ids=lambda state: security_groups)


def step_check_icmp_sec_rule(security_groups,
                             type,
                             code,
                             ip_addr=None,
                             ):
    if ip_addr.version == 4:
        et = constants.IPv4
        proto = constants.PROTO_NAME_ICMP
    else:
        et = constants.IPv6
        proto = constants.PROTO_NAME_ICMP_V6

    rule = SecurityGroupRule(
        ethertype=et,
        port_range_min=type,
        port_range_max=code,
        protocol=IP_PROTOCOL_MAP.get(proto),
        remote_ip_prefix=ip_addr
    )

    return CheckSecGroupRulePresentStep(
        rule=rule,
        get_security_group_ids=lambda state: security_groups)


class CheckSecGroupRulePresentStep(dsb.DiagnosticStep):
    name = _('Check security group rule present')

    def __init__(self, rule=None, get_security_group_ids=None, **kwargs):
        dsb.DiagnosticStep.__init__(self, **kwargs)
        self.get_security_group_ids = get_security_group_ids
        self.rule = rule

    @staticmethod
    def _get_security_rules_of_group(debug_agent, state,
                                     security_group_id):
        state_secgroups = state.get(c.STATE_ITEM_SECURITY_GROUPS, {})
        sg_rules = state_secgroups.get(security_group_id, None)
        if sg_rules is None:
            sg_rules = debug_agent.get_security_group_rules(security_group_id)
            state_secgroups[security_group_id] = sg_rules

        return sg_rules

    def diagnose(self, debug_agent, state):
        security_group_ids = self.get_security_group_ids(state)

        for sg in security_group_ids:
            security_rules = self._get_security_rules_of_group(debug_agent,
                                                               state, sg)

            for rule in security_rules:
                if security_rule_embodies(self.rule, rule):
                    return self.create_result_info(True)

        msg = _("Check security groups settings, there seems "
                "to be no rule allowing the requested traffic.")

        return self.create_result_info(False, message=msg)
