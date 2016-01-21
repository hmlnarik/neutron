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

import abc
import shlex
import six

from netaddr.core import AddrFormatError
from netaddr import IPAddress

from neutron._i18n import _
from neutron.agent.linux import ip_lib

from neutron.debug import constants as c
from neutron.debug import exceptions as exc


@six.add_metaclass(abc.ABCMeta)
class DiagnosticStep(object):
    def __init__(self, name=None):
        # Allow overriding default name in constructor to enable more specific
        # step names when desirable
        if name is not None:
            self.name = name

    def get_name(self):
        """Returns human-readable name of the diagnostic step.
        :return: Name of the step
        """
        return str(self.name)

    def __str__(self):
        return self.get_name()

    def create_result_info(self, step_result, message=None):
        return DiagnosticStepResult(self, step_result, message=message)

    @abc.abstractmethod
    def diagnose(self, debug_agent, state):
        """Method for performing actual diagnostic step.

        :param debug_agent: Debug agent
        :param state DiagnosticStepState: Debug state
        :return: None when the step should be completely ignored,
           otherwise single instance of DiagnosticStepResult or an iterable
           of these
        """
        pass


class DiagnosticStepResult(object):
    """
    Container holding result of a single diagnostic step execution.
    """

    def __init__(self, step, result, message=None):
        """
        Constructs DiagnosticStepResult instance.

        :param step: Name of the step
        :param result: Step result - may be bool or arbitrary string, but
                       should be short. Bool is converted into "ok" or "FAIL"
        :param message: Additional
        """

        self.result = result
        if type(result) is bool:
            self.result_message = (c.TEST_PASSED_MSG if result
                                   else c.TEST_FAILED_MSG)
        else:
            self.result_message = result

        self.step = step
        self.message = message
        self.next_steps = []

    def add_next_step(self, step):
        if step is not None:
            self.next_steps.append(step)

    def get_next_steps(self):
        return self.next_steps

    def get_step(self):
        return self.step

    def get_message(self):
        return self.message

    def get_result(self):
        return self.result

    def get_result_message(self):
        return self.result_message

    def __str__(self):
        return "%s: %s (%s)" % (self.step, self.result, self.message)


class DiagnosticStepState(dict):
    def __init__(self, **kwargs):
        dict.__init__(self, **kwargs)
        self.floating_to_fixed = {}
        self.ports = {}             # { port_id -> port_record }
        self.network_ports = {}     # { network_id -> [ port_ids ] }
        self.router_ports = {}      # { router_id -> [ port_ids ] }
        self.next_steps = []        # [ steps ] }
        self.ipaddr_to_port = {}    # { ip_addr -> port_id }

    def _add_ipaddr_to_port(self, ports):
        for port in ports:
            port_id = port['id']
            self.ports[port_id] = port

            for f in port.get('fixed_ips', []):
                if "ip_address" in f:
                    ip = IPAddress(f['ip_address'])
                    self.ipaddr_to_port[ip] = port['id']

    def add_floating_to_fixed_ip(self, floating_ip, fixed_ip, port_id):
        fl_ip = IPAddress(floating_ip)
        self.floating_to_fixed[fl_ip] = fixed_ip
        if port_id:
            self.ipaddr_to_port[fl_ip] = port_id

    def get_fixed_from_floating_ip(self, fixed_ip):
        fl_ip = IPAddress(fixed_ip)
        return self.floating_to_fixed.get(fl_ip, None)

    def get_floating_ips(self):
        return self.floating_to_fixed.keys()

    def get_port_from_ip_address(self, ip_address):
        port_id = self.ipaddr_to_port.get(IPAddress(ip_address), None)
        return self.ports.get(port_id, None)

    def add_network_ports(self, network_id, *ports):
        self.network_ports.setdefault(network_id, [])
        self.network_ports[network_id].extend([port['id'] for port in ports])
        self.ports.update({port['id']: port for port in ports})
        self._add_ipaddr_to_port(ports)

    def get_network_ports(self, network_id):
        return [
            self.ports.get(port_id, None)
            for port_id in self.network_ports.get(network_id, [])
        ]

    def add_router_ports(self, router_id, *ports):
        self.router_ports.setdefault(router_id, [])
        self.router_ports[router_id].extend([port['id'] for port in ports])
        self.ports.update({port['id']: port for port in ports})
        self._add_ipaddr_to_port(ports)

    def get_router_ports(self, router_id):
        return [
            self.ports.get(port_id, None)
            for port_id in self.router_ports.get(router_id, [])
        ]


@six.add_metaclass(abc.ABCMeta)
class ExecCmdWithIpFromNamespaceStep(DiagnosticStep):
    def __init__(self, namespace=None, target_ip_addr=None, **kwargs):
        DiagnosticStep.__init__(self, **kwargs)
        self.namespace = namespace
        self.target_ip_addr = target_ip_addr

    @staticmethod
    def _normalize_ip(ip):
        """
        Verifies that the given parameter represents correct
        IP address (either IPv4 or IPv6) and returns corresponding
        IPAddress instance.
        """

        try:
            target_ip = IPAddress(ip)
        except AddrFormatError:
            raise exc.InvalidIpAddressException(ip_address=ip)

        if target_ip.version not in [4, 6]:
            raise exc.InvalidIpAddressException(ip_address=ip)

        return target_ip

    def _record_already_processed(self, ip_address, state):
        """Check whether the record has been already processed, and if not,
        mark it as such.
        :return: True if the record has been processed already, False otherwise
        """
        record = "%s:%s" % (self.namespace if self.namespace else "",
                            ip_address)

        done_hosts_key = '%s:done' % self.__class__.__name__
        done_hosts = state.setdefault(done_hosts_key, set())

        if record in done_hosts:
            return True

        state[done_hosts_key].add(record)

        return False

    @abc.abstractmethod
    def get_command(self, state):
        """
        Returns command to be executed in the appropriate network namespace.
        Note that the command needs to be defined in rootwrap.d/debug.filters.

        :param state: Diagnostic state (before running the command)
        :return: Either string or array representation of the command and
                 its arguments.
        """
        pass

    @abc.abstractmethod
    def clone_for_ip_address(self, new_ip_address):
        """
        Returns a new instance of this command where target IP address
        is replaced with new_ip_address.

        This is used e.g. to ping a fixed IP address based on floating
        IP address.


        :param new_ip_address: IP address to target command to
        :return: None (if the command cannot be cloned) or cloned command
        """
        pass

    def diagnose(self, debug_agent, state):
        self.target_ip_addr = self._normalize_ip(self.target_ip_addr)

        # Check that the IP has not been processed from the given NS yet.
        # Skip this step if it had. This is to prevent endless loops
        if self._record_already_processed(self.target_ip_addr, state):
            return None

        res = self._execute_cmd(debug_agent, state)

        # If this step was performed using a floating IP and there is
        # a corresponding fixed IP, redo the same step with fixed IP
        fixed_ip = state.get_fixed_from_floating_ip(str(self.target_ip_addr))
        if fixed_ip and not res.get_result():
            next_step = self.clone_for_ip_address(fixed_ip)
            next_step.name = _("Retry the same step for fixed IP")
            res.add_next_step(next_step)

        return res

    def get_result_message_header(self):
        """
        Returns a header of detailed message shown to the user in the
        results table. By default, it contains target IP address and
        namespace.

        :return: see above
        """
        return _("IP: %(ip)s, NS: %(ns)s") % {
            'ip': self.target_ip_addr,
            'ns': self.namespace
        }

    def _execute_cmd(self, debug_agent, state):
        command_array = self.get_command(state)
        if type(command_array) is not list:
            command_array = shlex.split(command_array)

        message_header = self.get_result_message_header()

        root_ip = ip_lib.IPWrapper(self.namespace)

        try:
            root_ip.netns.execute(command_array,
                                  run_as_root=True,
                                  log_fail_as_error=False)
            result = self.create_result_info(True, message_header)
        except Exception as e:
            result = self.create_result_info(False,
                                             "%s\n%s" % (message_header,
                                                         e.message))

        return result
