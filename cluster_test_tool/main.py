#!/usr/bin/env python3
import sys
import re
import argparse
import functools
import getpass
import time
from datetime import datetime

from . import check
from . import config
from . import pam
from . import utils


def login(func):
    @functools.wraps(func)
    def login_func(*args, **kwargs):
        if config.LOGIN:
            print("###############")
        else:
            username = config.LOGIN_USER if config.LOGIN_USER else input("User name: ")
            if username == "" or username != "hacluster":
                utils.msg_error("User name is error!")
                sys.exit(1)
            password = config.LOGIN_PASSWORD if config.LOGIN_PASSWORD else getpass.getpass()

            pam_instance = pam.pam()
            pam_instance.authenticate(username, password)
            if pam_instance.code != 0:
                utils.msg_error(pam_instance.reason)
                sys.exit(pam_instance.code)
            print("###############")
            config.LOGIN = True

        func(*args, **kwargs)

    return login_func


@login
def kill_testcase(option):
    print("Testcase:           Force Kill \"{}\"".format(option.name))
    print("Systemd Controlled; {}".format(not config.MASK))
    print("Expected Result:    {}".format(option.expect))
    print("Looping times:      {}".format(config.LOOP))
    if not utils.ask("Run?"):
        return
    print()

    looping_count = 0
    while True:
        if not check_require(option):
            continue

        fence_info = ()
        if option.expect.startswith("Fence"):
            fence_info = utils.get_fence_info()

        if config.MASK:
            utils.msg_warn("Running \"{}\"".format(option.mask_cmd))
            utils.run_cmd(option.mask_cmd)

        utils.msg_warn("Trying to run \"{}\"".format(option.command))
        print('')
        utils.run_cmd(option.command)
        after_run(option, fence_info)

        looping_count += 1
        if config.LOOP:
            continue
        else:
            break


@login
def fence_node(node):
    print("Testcase:        Fence node \"{}\"".format(node))

    # check required commands exists
    required_commands = ['crm_node', 'stonith_admin', 'crm_attribute']
    for cmd in required_commands:
        if not utils.which(cmd):
            sys.exit(1)

    # check crm_node command
    if not utils.check_node_status(node, 'member'):
        utils.msg_error("\"{}\" not in cluster!".format(node))
        sys.exit(1)

    fence_enabled, fence_action, fence_timeout = utils.get_fence_info()
    # check whether stonith is enabled
    if not fence_enabled:
        sys.exit(1)
    # get stonith action
    if not fence_action:
        sys.exit(1)
    if not fence_timeout:
        fence_timeout = config.FENCE_TIMEOUT

    print("Expect Result:   {}".format(fence_action))
    print()
    if not utils.ask("Run?"):
        return

    import socket
    if node == socket.gethostname():
        # fence self
        utils.run_cmd(config.FENCE_SELF.format(node), wait=False)
        utils.msg_info("Waiting {}s for self {}...".format(fence_timeout, fence_action))
        time.sleep(int(fence_timeout))
        utils.msg_error("Am I Still live?:(")
        sys.exit(1)
    else:
        # fence other node
        utils.run_cmd(config.FENCE_NODE.format(node), wait=False)
        run_time = datetime.now().strftime("%s")
        utils.msg_info("Waiting {}s for node \"{}\" {}...".format(fence_timeout, node, fence_action))
        count = 0
        while count < int(fence_timeout):
            time.sleep(1)
            count += 1
            if utils.do_fence_happen(node, run_time) and \
               utils.check_node_status(node, 'lost'):
                utils.msg_info("Node \"{}\" has been fenced successfully".format(node))
                return
        utils.msg_error("Node {} Still live?:(".format(node))
        sys.exit(1)
        

def check_require(option):
    rc, pid = utils.get_process_status(option.name)
    if not rc:
        #utils.msg_error("Process {} is not running!".format(option.name))
        return False

    utils.msg_info("Process {}({}) is running...".format(option.name, pid))

    if option.expect.startswith("Fence"):
        if not utils.is_fence_enabled():
            return False
    return True


def after_run(option, fence_info):
    """
    if option.expect in ("restart", "open"):
        count = 0
        while count <= config.RESTART_TIMEOUT:
            time.sleep(0.1)
            rc, pid = utils.get_process_status(option.name)
            if rc:
                utils.msg_info("Success! Process {}({}) is restarted!".format(option.name, pid))
                if config.MASK:
                    utils.msg_info("Running \"{}\"".format(option.unmask_cmd))
                    utils.run_cmd(option.unmask_cmd)
                return
            else:
                count += 1
    """
    if option.expect.startswith("Fence"):
        fence_action = fence_info[1]
        if not fence_action:
            sys.exit(1)
        fence_timeout = fence_info[2]
        if fence_timeout is None:
            fence_timeout = config.FENCE_TIMEOUT
        utils.msg_info("Waiting {}s for self {}...".format(fence_timeout, fence_action))
        time.sleep(int(fence_timeout))
        utils.msg_error("Am I Still live?:(")
        sys.exit(1)


def run():
    try:
        parser = argparse.ArgumentParser(description='Cluster Testing Tool Set')

        group_basic = parser.add_argument_group('Basic Check')
        group_basic.add_argument('-e', '--env-check', dest='env_check', action="store_true",
                                 help='Check environment')
        group_basic.add_argument('-c', '--cluster-check', dest='cluster_check', action="store_true",
                                 help='Check cluster state')

        group_kill = parser.add_argument_group('Kill Process')
        for option in config.option_list:
            group_kill.add_argument(option.option,
                                    help=option.help,
                                    dest=option.dest,
                                    action="store_true")
        group_kill.add_argument('-m', '--mask-service', dest='mask', action="store_true",
                                help='mask related systemd service')
        group_kill.add_argument('-l', '--kill-loop', dest='loop', action="store_true",
                                help='kill process in loop')

        group_fence = parser.add_argument_group('Fence Node')
        group_fence.add_argument('--fence-node',
                                 help='Fence specific node',
                                 dest='fence_node',
                                 metavar='NODE')

        other_options = parser.add_argument_group('Other Options')
        other_options.add_argument('-d', '--debug', dest='debug', action='store_true',
                                   help='Print verbose debugging information')
        other_options.add_argument('-y', '--yes', dest='yes', action='store_true',
                                   help='Answer "yes" if asked to run the test')
        other_options.add_argument('-u', dest='user', metavar='USER',
                                   help='User for login')
        other_options.add_argument('-p', dest='password', metavar='PASSWORD',
                                   help='Password for login')

        args = parser.parse_args()

        if len(sys.argv) == 1:
            return

        if args.yes:
            config.PASS_ASK = True
        if args.user:
            config.LOGIN_USER = args.user
        if args.password:
            config.LOGIN_PASSWORD = args.password
        if args.mask:
            config.MASK = True
        if args.loop:
            config.LOOP = True
        if args.debug:
            config.DEBUG = True
        if args.env_check:
            check.check_environment()
        if args.cluster_check:
            check.check_cluster()
        if not utils.is_cluster_running():
            utils.msg_error("cluster is not running!")
            sys.exit(1)
        for option in config.option_list:
            if hasattr(args, option.dest) and getattr(args, option.dest):
                kill_testcase(option)
        if args.fence_node:
            return fence_node(args.fence_node)

    except KeyboardInterrupt:
        print("\nCtrl-C, leaving")
        sys.exit(1)
