
import unittest
from cluster_test_tool import utils


def get_output(cmd):
    rc, out, err = utils.run_cmd(cmd)
    if rc != 0:
        raise RuntimeError(err)
    return out


class TestUtils(unittest.TestCase):
    def test_me(self):
        self.assertEqual(utils.me(), get_output("hostname -s"))

    def test_now(self):
        self.assertEqual(utils.now(), get_output("date +\"%Y/%m/%d %H:%M:%S\""))

    def test_service_is_active(self):
        self.assertTrue(utils.service_is_active("corosync"))


if __name__ == '__main__':
    unittest.main()
