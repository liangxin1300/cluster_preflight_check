"""
Unitary tests for cluster_test_tool/check.py

:author: Xin Liang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.com

:since: 2019-07-05
"""

# pylint:disable=C0103,C0111,W0212,W0611

import unittest
import logging
from cluster_test_tool import check

try:
    from unittest import mock
except ImportError:
    import mock


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
 
    @mock.patch('cluster_test_tool.check.check_environment')
    @mock.patch('cluster_test_tool.check.check_cluster')
    @mock.patch('cluster_test_tool.main')
    def test_check(self, mock_main, mock_cluster, mock_env):
        mock_main.ctx.env_check = True
        mock_main.ctx.cluster_check = True
        check.check(mock_main.ctx)
        mock_cluster.assert_called_once_with()
        mock_env.assert_called_once_with()

    @mock.patch('cluster_test_tool.check.check_my_hostname_resolves')
    @mock.patch('cluster_test_tool.check.check_time_service')
    @mock.patch('cluster_test_tool.check.check_watchdog')
    @mock.patch('cluster_test_tool.check.check_firewall')
    def test_check_environment(self,
                               mock_firewall,
                               mock_watchdog,
                               mock_time,
                               mock_hostname):
        check.check_environment()
        mock_firewall.assert_called_once_with()
        mock_watchdog.assert_called_once_with()
        mock_time.assert_called_once_with()
        mock_hostname.assert_called_once_with()

    @mock.patch('cluster_test_tool.utils.TaskCheck')
    @mock.patch('cluster_test_tool.utils.this_node')
    @mock.patch('socket.gethostbyname')
    def test_check_my_hostname_resolves(self,
                                        mock_gethostbyname,
                                        mock_this_node,
                                        mock_task):
        mock_instance = mock.Mock()
        mock_task.return_value = mock_instance
        mock_this_node.return_value = "host1.com"

        check.check_my_hostname_resolves()

        mock_task.assert_called_once_with("Checking hostname resolvable")
        mock_this_node.assert_called_once_with()
        mock_gethostbyname.assert_called_once_with("host1.com")
        mock_instance.print_result.assert_called_once_with()

    @mock.patch('cluster_test_tool.utils.TaskCheck')
    @mock.patch('cluster_test_tool.utils.service_is_available')
    def test_check_time_service_not_found(self,
                                          mock_available,
                                          mock_task):
        mock_instance = mock.Mock()
        mock_task.return_value = mock_instance
        mock_available.side_effect = [False, False, False]

        check.check_time_service()
        
        mock_available.assert_has_calls([
            mock.call('chronyd.service'),
            mock.call('ntp.service'),
            mock.call('ntpd.service')
        ])
        mock_instance.warn.assert_called_once_with("No NTP service found.")
        mock_instance.print_result.assert_called_once_with()

    @mock.patch('cluster_test_tool.utils.TaskCheck')
    @mock.patch('cluster_test_tool.utils.service_is_available')
    @mock.patch('cluster_test_tool.utils.service_is_enabled')
    @mock.patch('cluster_test_tool.utils.service_is_active')
    def test_check_time_service_found(self,
                                      mock_active,
                                      mock_enabled,
                                      mock_available,
                                      mock_task):
        mock_instance = mock.Mock()
        mock_task.return_value = mock_instance
        mock_available.side_effect = [False, False, True]
        mock_active.return_value = True
        mock_enabled.return_value = True

        check.check_time_service()
        
        mock_available.assert_has_calls([
            mock.call('chronyd.service'),
            mock.call('ntp.service'),
            mock.call('ntpd.service')
        ])
        mock_instance.info.assert_has_calls([
            mock.call('ntpd.service is available'),
            mock.call('ntpd.service is enabled'),
            mock.call('ntpd.service is active')
        ])
        mock_enabled.assert_called_once_with("ntpd.service")
        mock_active.assert_called_once_with("ntpd.service")
        mock_instance.print_result.assert_called_once_with()

    @mock.patch('cluster_test_tool.check.check_cluster_service')
    def test_check_cluster_no_service(self, mock_cluster):
        mock_cluster.return_value = False
        check.check_cluster()
        mock_cluster.assert_called_once_with()

    @mock.patch('cluster_test_tool.check.check_cluster_service')
    @mock.patch('cluster_test_tool.check.check_fencing')
    @mock.patch('cluster_test_tool.check.check_nodes')
    @mock.patch('cluster_test_tool.check.check_resources')
    def test_check_cluster(self,
                           mock_resources,
                           mock_nodes,
                           mock_fencing,
                           mock_cluster):
        mock_cluster.return_value = True
        check.check_cluster()
        mock_cluster.assert_called_once_with()
        mock_fencing.assert_called_once_with()
        mock_nodes.assert_called_once_with()
        mock_resources.assert_called_once_with()
