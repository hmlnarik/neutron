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
from cliff import lister
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as client
import six

from neutron._i18n import _
from neutron.debug import constants as c
from neutron.debug import diagnostic_steps as ds
from neutron.debug import diagnostic_steps_base as dsb
from neutron.debug import diagnostic_steps_ns as ds_ns
from neutron.debug import diagnostic_steps_ping as ds_ping


@six.add_metaclass(abc.ABCMeta)
class DiagnoseCommand(client.NeutronCommand, lister.Lister):
    """
    Top-level class for diagnostic commands. It runs given diagnostic steps
    (see get_steps() method), collects results on the way, and manages
    requests to run additional steps from step execution results. Collected
    results are presented to the user via usual Lister methods.

    The descendants of this class should only need to override get_steps()
    method (and get_parser most likely too).
    """

    def get_debug_agent(self):
        return self.app.debug_agent

    @abc.abstractmethod
    def get_steps(self, args):
        """
        Returns diagnostic steps executed in this command

        :param args: Namespace with parsed arguments
        """
        pass

    def get_initial_diagnostic_state(self, args):
        """
        Returns initial instance of DiagnosticStepState
        :param args: Arguments passed to the command
        :return: Initialized state (empty state by default)
        """
        return dsb.DiagnosticStepState()

    def _run_diagnose(self, steps, state):
        def process_result(result):
            res = {'result': result}

            if result.get_next_steps():
                subres = self._run_diagnose(result.get_next_steps(), state)
                res['sub_steps'] = subres

            return res

        debug_agent = self.get_debug_agent()
        results = []
        if type(steps) is not list:
            steps = [steps]

        for s in steps:
            try:
                diag_result = s.diagnose(debug_agent, state)
                if diag_result is None:
                    continue

                if type(diag_result) not in [list, set, tuple]:
                    diag_result = [diag_result]

                res = [process_result(dr) for dr in diag_result]
                results.extend(res)

            except Exception as e:
                eres = dsb.DiagnosticStepResult(s, c.TEST_ABORTED_MSG, e)
                results.append(process_result(eres))

        return results

    def _indent(self, item, indent=0):
        indent_str = ("" if indent == 0
                      else c.INDENT_MARK % (c.INDENT_SPACE * (indent - 1)))

        return (
            indent_str + str(item[0]),
            str(item[1]),
            str(item[2])
        )

    def _single_result_to_list_item(self, item, columns, indent=0):
        res = [self._indent(utils.get_item_properties(item['result'],
                                                      columns),
                            indent)]

        for sub_step in item.get('sub_steps', []):
            res.extend(self._single_result_to_list_item(sub_step,
                                                        columns,
                                                        indent + 1))
        return res

    def take_action(self, args):
        steps = self.get_steps(args)
        state = self.get_initial_diagnostic_state(args)
        results = self._run_diagnose(steps, state)
        columns = ('step', 'result_message', 'message')

        table_items = []
        for res in results:
            table_items.extend(self._single_result_to_list_item(res, columns))

        return columns, table_items


class DiagnoseRouter(DiagnoseCommand):
    """
    Diagnose validity of router settings and verify that target IP
    can be pinged directly from the router. Target-IP address
    can be both fixed and floating.
    """

    def get_parser(self, prog_name):
        parser = super(DiagnoseRouter, self).get_parser(prog_name)
        parser.add_argument(
            '--timeout', metavar='<timeout>',
            default=10,
            help=_('Ping/Ncat timeout [sec]'))
        parser.add_argument(
            'router_id', metavar='ROUTER',
            help=_('ID or name of the router.'))
        parser.add_argument(
            'target_ips', metavar='TARGET-IP',
            nargs="+",
            help=_('Target IP addresses to test'))
        return parser

    def get_steps(self, args):
        res = []

        res.append(ds.ObtainRouterPortsAndNetworksStep(
            router_id=args.router_id))
        res.append(ds.ObtainNetworkPortsStep(
            get_ports_func=lambda state:
                state.get(c.STATE_ITEM_ROUTER_NETWORK_IDS, {})
                     .get(args.router_id, set())
        ))
        res.append(ds.ObtainFloatingToFixedIpStep())

        res.append(ds.CheckRouterAdminStateUpStep(router_id=args.router_id))
        res.append(ds.CheckPortsAdminStateUpStep(
            name=_('Check admin state of router ports'),
            get_ports_func=lambda state: state.get_router_ports(args.router_id)
        ))

        res.append(ds_ns.CheckRouterNamespaceExistenceStep(args.router_id))

        for ip in args.target_ips:
            kwargs = {
                'router_id': args.router_id,
                'target_ip_addr': ip
            }
            res.append(ds_ping.PingFromRouterNamespaceStep(**kwargs))
            res.append(ds.CheckTcpPortOpenFromRouterNamespaceStep(**kwargs))

        return res
