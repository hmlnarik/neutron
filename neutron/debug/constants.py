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


TEST_PASSED_MSG = _('ok')
TEST_FAILED_MSG = _('FAIL')
TEST_ABORTED_MSG = _('ABORTED')
INDENT_MARK = "%s  - "
INDENT_SPACE = "    "

# TODO(hmlnarik) Make the following commands customizable in the config file
PING_IPV4 = "ping -c 1 -w %(timeout)s %(destination)s"
PING_IPV6 = "ping6 -c 1 -w %(timeout)s %(destination)s"
TEST_TCP_OPEN_IPV4 = "nc -4 -w %(timeout)s %(destination)s %(port)s " \
                     "-e /bin/true"
TEST_TCP_OPEN_IPV6 = "nc -6 -w %(timeout)s %(destination)s %(port)s " \
                     "-e /bin/true"

# keys for the state map of diagnostic steps
STATE_ITEM_ROUTER_PORTS = 'router-ports'
STATE_ITEM_NETWORK_PORTS = 'network-ports'
STATE_ITEM_FLOATING_TO_FIXED = 'floating-to-fixed'
STATE_ITEM_ROUTER_NETWORK_IDS = 'router-network-ids'
STATE_ITEM_SECURITY_GROUPS = 'sec-groups'
