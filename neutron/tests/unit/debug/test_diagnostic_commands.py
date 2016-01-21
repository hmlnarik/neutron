# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
import testtools.assertions as a
import testtools.matchers as m

from neutron.debug import constants as c
from neutron.debug import diagnostic_commands as dc
from neutron.debug import diagnostic_steps_base as dsb
from neutron.tests import base


INDEX_STEP_NAME = 0
INDEX_RESULT = 1
INDEX_MESSAGE = 2


class MyApp(object):
    def __init__(self, _stdout):
        self.stdout = _stdout


class TestDiagnoseCommand(base.BaseTestCase):
    def setUp(self):
        super(TestDiagnoseCommand, self).setUp()
        mock_std = mock.Mock()
        self.app = MyApp(mock_std)
        self.app.debug_agent = mock.Mock()

    def _test_cmd(self, steps):
        cmd = Cmd(self.app, None, steps)
        cmd_parser = cmd.get_parser('cmd')
        parsed_args = cmd_parser.parse_args([])
        res = cmd.take_action(parsed_args)

        # Expect list/tuple of size 2 - ([captions], [item1, item2, ...])
        a.assert_that(res, m.HasLength(2))
        a.assert_that(res[0], m.ContainsAll(['step', 'result_message',
                                             'message']))
        a.assert_that(res[1], m.IsInstance(list))

        return res[1]

    def test_single_step_single_result(self):
        res = self._test_cmd([
            StepReturningOneResult()
        ])

        a.assert_that(res, m.HasLength(1))
        a.assert_that(str(res[0][INDEX_STEP_NAME]),
                      m.Equals(StepReturningOneResult.name))

    def test_change_step_name(self):
        res = self._test_cmd([
            StepReturningOneResult(name="another_name")
        ])

        a.assert_that(res, m.HasLength(1))
        a.assert_that(str(res[0][INDEX_STEP_NAME]),
                      m.Equals("another_name"))

    def test_single_step_multiple_results(self):
        res = self._test_cmd([
            StepReturningThreeResults()
        ])

        a.assert_that(res, m.HasLength(3))
        for step_index in range(0, 3):
            a.assert_that(str(res[step_index][INDEX_STEP_NAME]),
                          m.Equals(StepReturningThreeResults.name))
            a.assert_that(str(res[step_index][INDEX_MESSAGE]),
                          m.Equals("result %d" % (step_index + 1)))

    def test_chained_execution(self):
        res = self._test_cmd([
            StepReturningOneResult(),           # 1 result
            StepReturningNone(),                # 0 results
            StepReturningThreeResults(),        # 3 results
            StepRequestingStep1Reexecution()    # 2 results
        ])

        a.assert_that(res, m.HasLength(1 + 0 + 3 + 2))
        a.assert_that(str(res[0][INDEX_STEP_NAME]),
                      m.Equals(StepReturningOneResult.name))

        for step_index in range(1, 4):
            a.assert_that(str(res[step_index][INDEX_STEP_NAME]),
                          m.Equals(StepReturningThreeResults.name))

        a.assert_that(str(res[4][INDEX_STEP_NAME]),
                      m.Equals(StepRequestingStep1Reexecution.name))
        a.assert_that(str(res[5][INDEX_STEP_NAME]),
                      m.Equals((c.INDENT_MARK % "") +
                               StepRequestingStep1Reexecution.name))

    def test_step_exception(self):
        res = self._test_cmd([
            StepRaiseException()
        ])

        a.assert_that(res, m.HasLength(1))
        a.assert_that(str(res[0][INDEX_STEP_NAME]),
                      m.Equals(StepRaiseException.name))
        a.assert_that(str(res[0][INDEX_MESSAGE]),
                      m.Contains("<Hello>"))

    def test_step_execution_request(self):
        res = self._test_cmd([
            StepRequestingStep1Reexecution()
        ])

        a.assert_that(res, m.HasLength(2))
        a.assert_that(str(res[0][INDEX_STEP_NAME]),
                      m.Equals(StepRequestingStep1Reexecution.name))
        a.assert_that(str(res[1][INDEX_STEP_NAME]),
                      m.Equals((c.INDENT_MARK % "") +
                               StepRequestingStep1Reexecution.name))

    def test_nested_step_execution_request(self):
        res = self._test_cmd([
            Step2RequestingStep1Execution()
        ])

        a.assert_that(res, m.HasLength(3))
        a.assert_that(str(res[0][INDEX_STEP_NAME]),
                      m.Equals(Step2RequestingStep1Execution.name))
        a.assert_that(str(res[1][INDEX_STEP_NAME]),
                      m.Equals((c.INDENT_MARK % "") +
                               StepRequestingStep1Reexecution.name))
        a.assert_that(str(res[2][INDEX_STEP_NAME]),
                      m.Equals((c.INDENT_MARK % (c.INDENT_SPACE * 1)) +
                               StepRequestingStep1Reexecution.name))

    def test_single_step_returning_none(self):
        res = self._test_cmd([
            StepReturningNone()
        ])

        a.assert_that(res, m.HasLength(0))

#
# Auxiliary classes follow:
#


class StepRequestingStep1Reexecution(dsb.DiagnosticStep):
    name = "Step requesting Step1 reexecution"

    def diagnose(self, debug_agent, state):
        reexecute = state.get('StepRequestingStep1Reexecution', True)
        state['StepRequestingStep1Reexecution'] = False

        res = self.create_result_info(a)
        if reexecute:
            res.add_next_step(StepRequestingStep1Reexecution())

        return res


class Step2RequestingStep1Execution(dsb.DiagnosticStep):
    name = "Step _2_ requesting Step1 execution"

    def diagnose(self, debug_agent, state):
        res = self.create_result_info(True)
        res.add_next_step(StepRequestingStep1Reexecution())

        return res


class StepReturningThreeResults(dsb.DiagnosticStep):
    name = "Step returning three results"

    def diagnose(self, debug_agent, state):
        res = [self.create_result_info(True, "result 1"),
               self.create_result_info(False, "result 2"),
               self.create_result_info(True, "result 3")]

        return res


class StepReturningOneResult(dsb.DiagnosticStep):
    name = "Step returning one result"

    def diagnose(self, debug_agent, state):
        return self.create_result_info(True)


class StepReturningNone(dsb.DiagnosticStep):
    name = "Step returning None"

    def diagnose(self, debug_agent, state):
        return None


class StepRaiseException(dsb.DiagnosticStep):
    name = "Step raising an exception"

    def diagnose(self, debug_agent, state):
        raise Exception("<Hello>")


class Cmd(dc.DiagnoseCommand):
    def __init__(self, app, app_args, steps):
        dc.DiagnoseCommand.__init__(self, app=app, app_args=app_args)
        self.steps = steps

    def get_steps(self, args):
        return self.steps
