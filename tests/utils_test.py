"""
Unitary tests for cluster_test_tool/utils.py

:author: Xin Liang
:organization: SUSE Linux GmbH
:contact: XLiang@suse.com

:since: 2019-07-01
"""

# pylint:disable=C0103,C0111,W0212,W0611

import unittest
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

    def test_me(self):
        self.assertEqual(utils.me(), get_output("hostname -s"))

    def test_now(self):
        self.assertEqual(utils.now(), get_output("date +\"%Y/%m/%d %H:%M:%S\""))

    def test_service_is_active(self):
        self.assertTrue(utils.service_is_active("dbus"))

    @mock.patch('cluster_test_tool.utils.run_cmd')
    def test_corosync_port(self, mock_run_cmd):
        mock_run_cmd.return_value = "5045\n5047"
        result = utils.corosync_port()
        expected = [5045, 5047]
        self.assertListEqual(result, expected)
        mock_run_cmd.assert_called_once_with("corosync-cmapctl |awk -F'= ' 'BEGIN {rc=1}/mcastport/{print $2; rc=0}END{exit rc}'")
