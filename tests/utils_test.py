"""
Unitary tests for cluster_test_tool/utils.py

:author: Xin Liang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.com

:since: 2019-07-01
"""

# pylint:disable=C0103,C0111,W0212,W0611

import unittest
import logging
from cluster_test_tool import utils

try:
    from unittest import mock
except ImportError:
    import mock


def get_output(cmd):
    rc, out, err = utils.run_cmd(cmd)
    if rc != 0:
        raise RuntimeError(err)
    return out


class TestUtils(unittest.TestCase):
    '''
    Unitary tests for cluster_test_tool/utils.py
    '''

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

        logging.basicConfig(level=logging.INFO)

    def setUp(self):
        """
        Test setUp.
        """

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('cluster_test_tool.utils.datetime')
    def test_now(self, mock_datetime):
        mock_datetime.return_value = "2019/07/02 16:44:03"
        result = utils.now()
        self.assertEqual(result, "2019/07/02 16:44:03")
        mock_datetime.assert_called_once_with()

    @mock.patch('socket.gethostname')
    def test_me(self, mock_hostname):
        mock_hostname.return_value = "node1.com"
        result = utils.me()
        self.assertEqual(result, "node1.com")
        mock_hostname.assert_called_once_with()

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_get_property(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, '60s', None)
        result = utils.get_property('stonith-timeout')
        self.assertEqual(result, '60s')
        mock_run_cmd.assert_called_once_with("crm configure get_property stonith-timeout")

    @mock.patch('cluster_test_tool.utils.get_property')
    def test_fence_enabled(self, mock_property):
        mock_property.return_value = "true"
        result = utils.fence_enabled()
        self.assertTrue(result)
        mock_property.assert_called_once_with('stonith-enabled')

    @mock.patch('cluster_test_tool.utils.get_property')
    @mock.patch('re.match')
    def test_get_fence_timeout(self, mock_match, mock_property):
        mock_property.return_value = '60s'
        mock_match.return_value = True
        result = utils.get_fence_timeout()
        self.assertEqual(result, '60')
        mock_property.assert_called_once_with('stonith-timeout')
        mock_match.assert_called_once_with('[0-9]+(s|)$', '60s')

    @mock.patch('cluster_test_tool.utils.fence_enabled')
    @mock.patch('cluster_test_tool.utils.get_fence_action')
    @mock.patch('cluster_test_tool.utils.get_fence_timeout')
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

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_service_is_active(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, None, None)
        result = utils.service_is_active('corosync.service')
        self.assertTrue(result)
        mock_run_cmd.assert_called_once_with('systemctl -q is-active corosync.service')

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_service_is_enabled(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, None, None)
        result = utils.service_is_enabled('corosync.service')
        self.assertTrue(result)
        mock_run_cmd.assert_called_once_with('systemctl is-enabled corosync.service')

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_grep_output(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "Tue Jul  2 13:48:13 CST 2019", None)
        result = utils.grep_output("date", 'Jul')
        self.assertTrue(result)
        mock_run_cmd.assert_called_once_with("date")

    @mock.patch('cluster_test_tool.utils.grep_output')
    def test_service_is_available(self, mock_grep):
        mock_grep.return_value = "ntp.service"
        result = utils.service_is_available("ntp.service")
        self.assertEqual(result, "ntp.service")
        mock_grep.assert_called_once_with("systemctl list-unit-files ntp.service",
                                          "ntp.service")

    @mock.patch('cluster_test_tool.utils.service_is_active')
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

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_package_is_installed(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, None, None)
        result = utils.package_is_installed("crmsh")
        self.assertEqual(result, True)
        mock_run_cmd.assert_called_once_with("rpm -q --quiet crmsh")

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_corosync_port(self, mock_run_cmd):
        mock_run_cmd.return_value = (0, "5045\n5047", None)
        result = utils.corosync_port()
        expected = ['5045', '5047']
        self.assertListEqual(result, expected)
        mock_run_cmd.assert_called_once_with("corosync-cmapctl |awk -F'= ' 'BEGIN {rc=1}/mcastport/{print $2; rc=0}END{exit rc}'")
