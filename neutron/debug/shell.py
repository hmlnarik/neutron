# Copyright 2012,  Nachi Ueno,  NTT MCL,  Inc.
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

import argparse
import sys

from oslo_config import cfg
from oslo_utils import importutils

from neutron._i18n import _
from neutron.agent.common import config
from neutron.agent.common import utils
from neutron.agent.linux import interface
from neutron.common import config as common_config
from neutron.debug import debug_agent
from neutronclient.common import exceptions as exc
from neutronclient import shell

COMMAND_V2 = {
    'probe-create': importutils.import_class(
        'neutron.debug.commands.CreateProbe'),
    'probe-delete': importutils.import_class(
        'neutron.debug.commands.DeleteProbe'),
    'probe-list': importutils.import_class(
        'neutron.debug.commands.ListProbe'),
    'probe-clear': importutils.import_class(
        'neutron.debug.commands.ClearProbe'),
    'probe-exec': importutils.import_class(
        'neutron.debug.commands.ExecProbe'),
    'ping-all': importutils.import_class(
        'neutron.debug.commands.PingAll'),
    'diagnose-router': importutils.import_class(
        'neutron.debug.diagnostic_commands.DiagnoseRouter'),
    #TODO(nati)  ping, netcat , nmap, bench
}
COMMANDS = {'2.0': COMMAND_V2}


class NeutronDebugShell(shell.NeutronShell):
    def __init__(self, api_version):
        super(NeutronDebugShell, self).__init__(api_version)
        for k, v in COMMANDS[api_version].items():
            self.command_manager.add_command(k, v)

    class ExtendListAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            arg_value = getattr(args, self.dest, [])
            arg_value.extend([option_string, values])
            setattr(args, self.dest, arg_value)

    def build_option_parser(self, description, version):
        parser = super(NeutronDebugShell, self).build_option_parser(
            description, version)
        config_file = (shell.env('NEUTRON_TEST_CONFIG_FILE') or
                       shell.env('QUANTUM_TEST_CONFIG_FILE'))
        default = ["--config-file", config_file] if config_file else []

        parser.add_argument(
            '--config-file',
            default=default,
            dest="config_opts",
            action=NeutronDebugShell.ExtendListAction,
            metavar='PATH',
            help=_('Config file for interface driver '
                   '(You may also use l3_agent.ini)'))
        parser.add_argument(
            '--config-dir',
            default=default,
            dest="config_opts",
            action=NeutronDebugShell.ExtendListAction,
            metavar='DIR',
            help=_('Directories with config file for interface driver'))
        return parser

    def register_opts(self, conf):
        conf.register_opts(interface.OPTS)
        conf.register_opts(config.EXT_NET_BRIDGE_OPTS)
        config.register_interface_driver_opts_helper(conf)

    def initialize_app(self, argv):
        super(NeutronDebugShell, self).initialize_app(argv)
        if not self.options.config_opts:
            raise exc.CommandError(
                _("You must provide a config file for bridge -"
                  " either --config-file or env[NEUTRON_TEST_CONFIG_FILE]"))
        client = self.client_manager.neutron
        self.register_opts(cfg.CONF)
        common_config.init(self.options.config_opts)
        config.setup_logging()
        driver = utils.load_interface_driver(cfg.CONF)
        self.debug_agent = debug_agent.NeutronDebugAgent(cfg.CONF,
                                                         client,
                                                         driver)


def main(argv=None):
    return NeutronDebugShell(shell.NEUTRON_API_VERSION).run(
        argv or sys.argv[1:])
