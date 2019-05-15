#!/usr/bin/env python3
import sys
import re
import argparse
import functools
import getpass
import time
import threading
from datetime import datetime

from . import check
from . import config
from . import pam
from . import utils


class Context(object):
    def __setattr__(self, name, value):
        super().__setattr__(name, value)


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


def kill_testcase(context):
    '''
    --kill-sbd:           restarted or fenced
    --kill-sbd -l         fenced
    --kill-corosync       restarted or fenced
    --kill-corosync -l    fenced
    --kill-pacemakerd     restarted
    --kill-pacemakerd -l  blocked by bsc#1111692
    '''
    def print_header(context):
        print("Testcase:         Force Kill \"{}\"".format(context.current_kill))
        print("Expected Result:  {}".format(context.expected))
        print("Looping:          {}".format(context.loop))

    def check_restarted(context):
        count = 0
        while count < 10:
            rc, pid = utils.get_process_status(context.current_kill)
            if rc:
                utils.msg_info("Success! Process {}({}) is restarted!".format(context.current_kill, pid))
                return
            time.sleep(0.5)
            count += 1
        utils.msg_error("Process {} is not restarted!".format(context.current_kill))

    def kill(context):
        if "Fenced" in context.expected and not utils.fence_enabled():
            utils.msg_error("stonith is not enabled!")
            sys.exit(1)

        thread_check = threading.Thread(target=utils.anyone_kill_me)

        while True:
            if not is_process_running(context):
                continue

            utils.msg_warn("Trying to run \"{}\"".format(context.cmd))
            utils.run_cmd(context.cmd)

            if not thread_check.is_alive():
                thread_check.start()

            if not context.loop:
                break
            # endless loop will lead to fence

        check_restarted(context)


    expected = {
        'sbd':        ('Restart|Fenced', 'Fenced'),
        'corosync':   ('Restart|Fenced', 'Fenced'),
        'pacemakerd': ('Restart', None),
    }

    for case in ('sbd', 'corosync', 'pacemakerd'):
        if getattr(context, case):
            if case == 'pacemakerd' and context.loop:
                return #blocked by bsc#1111692

            context.current_kill = case
            context.expected = expected[case][1] if context.loop else expected[case][0]
            context.cmd = r'killall -9 {}'.format(case)

            print_header(context)
            if not utils.ask("Run?"):
                return

            kill(context)
    """
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
        """

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
        

def is_process_running(context):
    rc, pid = utils.get_process_status(context.current_kill)
    if not rc:
        return False
    utils.msg_info("Process {}({}) is running...".format(context.current_kill, pid))
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
    """


def parse_argument(context):
    parser = argparse.ArgumentParser(description='Cluster Testing Tool Set',
                                     allow_abbrev=False,
                                     add_help=False)

    parser.add_argument('-e', '--env-check', dest='env_check', action='store_true',
                             help='Check environment')
    parser.add_argument('-c', '--cluster-check', dest='cluster_check', action='store_true',
                             help='Check cluster state')

    group_kill = parser.add_mutually_exclusive_group()
    group_kill.add_argument('--kill-sbd', dest='sbd', action='store_true',
                            help='kill sbd daemon')
    group_kill.add_argument('--kill-corosync', dest='corosync', action='store_true',
                            help='kill corosync daemon')
    group_kill.add_argument('--kill-pacemakerd', dest='pacemakerd', action='store_true',
                            help='kill pacemakerd daemon')
    parser.add_argument('-l', '--kill-loop', dest='loop', action='store_true',
                            help='kill process in loop')

    parser.add_argument('--fence-node', dest='fence_node', metavar='NODE',
                             help='Fence specific node')

    other_options = parser.add_argument_group('other options')
    other_options.add_argument('-d', '--debug', dest='debug', action='store_true',
                               help='Print verbose debugging information')
    other_options.add_argument('-y', '--yes', dest='yes', action='store_true',
                               help='Answer "yes" if asked to run the test')
    other_options.add_argument('-u', dest='user', metavar='USER',
                               help='User for login')
    other_options.add_argument('-p', dest='password', metavar='PASSWORD',
                               help='Password for login')
    other_options.add_argument('-h', '--help', dest='help', action='store_true',
                               help='show this help message and exit')

    args = parser.parse_args()
    if args.help:
        parser.print_help()
        sys.exit(0)
    for arg in vars(args):
        setattr(context, arg, getattr(args, arg))


def run(context):
    parse_argument(context)

    try:
        check.check(context)
        kill_testcase(context)
        #fence_node(ctx)

    except KeyboardInterrupt:
        print("\nCtrl-C, leaving")
        sys.exit(1)
    """
    try:

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

    """

ctx = Context()
