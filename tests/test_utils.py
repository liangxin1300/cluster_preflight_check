"""
Unitary tests for cluster_preflight_check/utils.py

:author: Xin Liang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.com

:since: 2019-07-01
"""

# pylint:disable=C0103,C0111,W0212,W0611

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
import logging
import datetime

try:
    from unittest import mock
except ImportError:
    import mock

from cluster_preflight_check import utils, main


class TestUtils(unittest.TestCase):
    '''
    Unitary tests for cluster_preflight_check/utils.py
    '''

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

        logging.basicConfig(level=logging.INFO)

    @mock.patch('cluster_preflight_check.utils.now')
    @mock.patch('cluster_preflight_check.main')
    def setUp(self, mock_main, mock_now):
        """
        Test setUp.
        """
        '''
        mock_now.return_value = "2019/07/10 01:15:15"
        mock_main.return_value = mock.Mock()
        self.task = utils.Task("project testing")
        self.task_check = utils.TaskCheck("TaskCheck testing")
        '''

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('socket.gethostname')
    def test_me(self, mock_hostname):
        mock_hostname.return_value = "node1.com"
        result = utils.me()
        self.assertEqual(result, "node1.com")
        mock_hostname.assert_called_once_with()
    
    @mock.patch('cluster_preflight_check.utils.datetime')
    def test_now(self, mock_datetime):
        mock_now = mock.Mock()
        mock_datetime.now.return_value = mock_now
        mock_now.strftime.return_value = "2019/07/05 14:44:55"
        result = utils.now()
        self.assertEqual(result, "2019/07/05 14:44:55")
        mock_datetime.now.assert_called_once_with()
        mock_now.strftime.assert_called_once_with("%Y/%m/%d %H:%M:%S")

    @mock.patch('cluster_preflight_check.utils.msg_raw')
    def test_msg_info(self, mock_msg_raw):
        mock_msg_raw.return_value = mock.Mock()
        utils.msg_info("test")
        mock_msg_raw.assert_called_once_with(logging.INFO, "test", True)

    @mock.patch('cluster_preflight_check.utils.msg_raw')
    def test_msg_warn(self, mock_msg_raw):
        mock_msg_raw.return_value = mock.Mock()
        utils.msg_warn("test")
        mock_msg_raw.assert_called_once_with(logging.WARNING, "test", True)

    @mock.patch('cluster_preflight_check.utils.msg_raw')
    def test_msg_error(self, mock_msg_raw):
        mock_msg_raw.return_value = mock.Mock()
        utils.msg_error("test")
        mock_msg_raw.assert_called_once_with(logging.ERROR, "test", True)

    def test_get_handler(self):
        mock_handler1 = mock.Mock(_name="test1_handler")
        mock_handler2 = mock.Mock(_name="test2_handler")
        mock_logger = mock.Mock(handlers=[mock_handler1, mock_handler2])
        res = utils.get_handler(mock_logger, "test1_handler")
        self.assertEqual(res, mock_handler1)

    @mock.patch('os.getuid')
    def test_is_root(self, mock_getuid):
        mock_getuid.return_value = 0
        self.assertEqual(utils.is_root(), True)
        mock_getuid.assert_called_once_with()
    '''
    @mock.patch('cluster_preflight_check.main')
    def test_msg_raw(self, mock_main):
        utils.msg_raw(logging.INFO, "testing logger")
        mock_main.ctx.logger.log.assert_called_once_with(logging.INFO, "testing logger")

    @mock.patch('cluster_preflight_check.main')
    def test_msg_raw_disable_stdout(self, mock_main):
        utils.msg_raw(logging.INFO, "testing logger", to_stdout=False)
        context = mock_main.ctx
        context.logger.removeHandler.assert_called_once_with(context.logger_stdout_handler)
        context.logger.log.assert_called_once_with(logging.INFO, "testing logger")
        context.logger.addHandler.assert_called_once_with(context.logger_stdout_handler)



    @mock.patch('cluster_preflight_check.utils.msg_info')
    def test_task_info(self, mock_info):
        self.task.msg_append = mock.Mock()
        self.task.info("test")
        self.task.msg_append.assert_called_once_with("info", "test")
        mock_info.assert_called_once_with("test", to_stdout=False)

    @mock.patch('cluster_preflight_check.utils.msg_warn')
    def test_task_warn(self, mock_warn):
        self.task.msg_append = mock.Mock()
        self.task.warn("test")
        self.task.msg_append.assert_called_once_with("warn", "test")
        mock_warn.assert_called_once_with("test", to_stdout=False)

    @mock.patch('cluster_preflight_check.utils.msg_error')
    def test_task_error(self, mock_error):
        self.task.msg_append = mock.Mock()
        self.task.error("test")
        self.task.msg_append.assert_called_once_with("error", "test")
        mock_error.assert_called_once_with("test", to_stdout=False)

    @mock.patch('cluster_preflight_check.utils.now')
    def test_task_msg_append(self, mock_now):
        mock_now.return_value = "2019/01/01"
        self.task.msg_append("error", "test msg_append")
        self.assertFalse(self.task.passed)
        expected = ("error", "test msg_append", "2019/01/01")
        self.assertTupleEqual(self.task.messages[-1], expected)

    def test_task_build_base_result(self):
        self.task.build_base_result()
        self.assertEqual(self.task.result["Timestamp"], "2019/07/10 01:15:15")
        self.assertEqual(self.task.result["Description"], "project testing")
        self.assertEqual(len(self.task.result["Messages"]), 0)

    @mock.patch('cluster_preflight_check.main')
    def test_task_check_to_stdout(self, mock_main):
        self.task_check.info("service1 is available")
        self.task_check.warn("service2 is disabled")
        self.task_check.to_stdout()
        context = mock_main.ctx
        context.logger.removeHandler.assert_called_once_with(context.logger_stdout_handler)

    @mock.patch('cluster_preflight_check.utils.run_cmd')
    def test_get_property(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, '60s', None)
        result = utils.get_property('stonith-timeout')
        self.assertEqual(result, '60s')
        mock_run_cmd.assert_called_once_with("crm configure get_property stonith-timeout")

    @mock.patch('cluster_preflight_check.utils.get_property')
    def test_fence_enabled(self, mock_property):
        mock_property.return_value = "true"
        result = utils.fence_enabled()
        self.assertTrue(result)
        mock_property.assert_called_once_with('stonith-enabled')

    @mock.patch('cluster_preflight_check.utils.get_property')
    @mock.patch('re.match')
    def test_get_fence_timeout(self, mock_match, mock_property):
        mock_property.return_value = '60s'
        mock_match.return_value = True
        result = utils.get_fence_timeout()
        self.assertEqual(result, '60')
        mock_property.assert_called_once_with('stonith-timeout')
        mock_match.assert_called_once_with('[0-9]+(s|)$', '60s')

    @mock.patch('cluster_preflight_check.utils.fence_enabled')
    @mock.patch('cluster_preflight_check.utils.get_fence_action')
    @mock.patch('cluster_preflight_check.utils.get_fence_timeout')
    def test_get_fence_info(self, mock_timeout, mock_action, mock_enabled):
        mock_enabled.return_value = True
        mock_action.return_value = "reboot"
        mock_timeout.return_value = 60
        result = utils.get_fence_info()
        expected = (True, "reboot", 60)
        self.assertTupleEqual(result, expected)
        mock_enabled.assert_called_once_with()
        mock_action.assert_called_once_with()
        mock_timeout.assert_called_once_with()

    @mock.patch('cluster_preflight_check.utils.run_cmd')
    def test_service_is_active(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, None, None)
        result = utils.service_is_active('corosync.service')
        self.assertTrue(result)
        mock_run_cmd.assert_called_once_with('systemctl -q is-active corosync.service')

    @mock.patch('cluster_preflight_check.utils.run_cmd')
    def test_service_is_enabled(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, None, None)
        result = utils.service_is_enabled('corosync.service')
        self.assertTrue(result)
        mock_run_cmd.assert_called_once_with('systemctl is-enabled corosync.service')

    @mock.patch('cluster_preflight_check.utils.run_cmd')
    def test_grep_output(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "Tue Jul  2 13:48:13 CST 2019", None)
        result = utils.grep_output("date", 'Jul')
        self.assertTrue(result)
        mock_run_cmd.assert_called_once_with("date")

    @mock.patch('cluster_preflight_check.utils.grep_output')
    def test_service_is_available(self, mock_grep):
        mock_grep.return_value = "ntp.service"
        result = utils.service_is_available("ntp.service")
        self.assertEqual(result, "ntp.service")
        mock_grep.assert_called_once_with("systemctl list-unit-files ntp.service",
                                          "ntp.service")

    @mock.patch('cluster_preflight_check.utils.service_is_active')
    def test_is_cluster_running(self, mock_is_active):
        mock_is_active.side_effect = [True, False]
        result = utils.is_cluster_running()
        self.assertFalse(result)
        mock_is_active.assert_has_calls([
            mock.call("corosync"),
            mock.call("pacemaker")
        ])

    @mock.patch('os.uname')
    def test_this_node(self, mock_uname):
        mock_uname.return_value = (None, "node-1.com")
        result = utils.this_node()
        self.assertEqual(result, "node-1.com")
        mock_uname.assert_called_once_with()

    @mock.patch('cluster_preflight_check.utils.run_cmd')
    def test_package_is_installed(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, None, None)
        result = utils.package_is_installed("crmsh")
        self.assertEqual(result, True)
        mock_run_cmd.assert_called_once_with("rpm -q --quiet crmsh")

    @mock.patch('cluster_preflight_check.utils.run_cmd')
    def test_corosync_port(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "5045\n5047", None)
        result = utils.corosync_port()
        expected = ['5045', '5047']
        self.assertListEqual(result, expected)
        mock_run_cmd.assert_called_once_with("corosync-cmapctl |awk -F'= ' 'BEGIN {rc=1}/mcastport/{print $2; rc=0}END{exit rc}'")
    '''
