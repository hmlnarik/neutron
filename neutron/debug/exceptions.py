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
from neutron.common import exceptions as n_exc


class InvalidIpAddressException(n_exc.NeutronException):
    message = _("Invalid IP address: %(ip_address)s")


class UnknownIpAddressVersionException(n_exc.NeutronException):
    message = _("Unknown IP address version: %(ip_address)s")


class InvalidArgumentError(n_exc.NeutronException):
    message = _("Invalid arguments given: %(reason)s")
