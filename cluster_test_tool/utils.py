import subprocess
import os
import re
from datetime import datetime

from . import config


CRED = '\033[31m'
CYELLOW = '\033[33m'
CGREEN = '\033[32m'
CEND = '\033[0m'
NOW = "[%s] " % datetime.now().strftime('%Y/%m/%d %H:%M:%S')

def msg_info(msg):
    print(NOW + CGREEN + "INFO: " + CEND + msg)


def msg_warn(msg):
    print(NOW + CYELLOW + "WARN: " + CEND + msg)


def msg_error(msg):
    print(NOW + CRED + "ERROR: " + CEND + msg)


def to_ascii(s):
    """Convert the bytes string to a ASCII string
    Usefull to remove accent (diacritics)"""
    if s is None:
        return s
    if isinstance(s, str):
        return s
    try:
        return str(s, 'utf-8')
    except UnicodeDecodeError:
        if config.core.debug or options.regression_tests:
            import traceback
            traceback.print_exc()
        return s


def ask(msg):
    if config.PASS_ASK:
        return True
    msg += ' '
    if msg.endswith('? '):
        msg = msg[:-2] + ' (y/n)? '

    while True:
        try:
            ans = input(msg)
        except EOFError:
            ans = 'n'
        if ans:
            ans = ans[0].lower()
            if ans in 'yn':
                return ans == 'y'


def run_cmd(cmd, input_s=None, shell=True, wait=True):
    '''
    Run a cmd, return (rc, stdout, stderr)
    '''
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=input_s and subprocess.PIPE or None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if wait:
        stdout_data, stderr_data = proc.communicate(input_s)
        return (proc.returncode,
                to_ascii(stdout_data).strip(),
                to_ascii(stderr_data).strip())
    else:
        return (proc.returncode, None, None)


def get_process_status(s):
    """
    Returns true if argument is the name of a running process.

    s: process name
    returns Boolean and pid
    """
    from os.path import join, basename
    # find pids of running processes
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            cmdline = open(join('/proc', pid, 'cmdline'), 'rb').read()
            procname = basename(to_ascii(cmdline).replace('\x00', ' ').split(' ')[0])
            if procname == s:
                return True, pid
        except EnvironmentError:
            # a process may have died since we got the list of pids
            pass
    return False, -1


def get_property(name):
    cmd = "crm configure get_property " + name
    rc, stdout, stderr = run_cmd(cmd)
    if rc != 0:
        msg_error(stderr)
        return None
    else:
        return stdout


def get_fence_action():
    fence_action = get_property('stonith-action')
    if fence_action is None or \
       fence_action not in ['off', 'poweroff', 'reboot']:
        msg_error("Cluster property \"stonith-action\" should be reboot|off|poweroff")
        return None
    return fence_action


def is_fence_enabled():
    fence_enabled = get_property('stonith-enabled')
    if fence_enabled and fence_enabled.lower() == "true":
        return True
    else:
        msg_warn("Cluster property \"stonith-enabled\" should be set \"true\"")
        return False


def get_fence_timeout():
    fence_timeout = get_property('stonith-timeout')
    if fence_timeout is None:
        return None
    if re.match('[0-9]+(s|)$', fence_timeout):
        return fence_timeout.strip('s')
    else:
        return None


def get_fence_info():
    fence_enabled = False
    if is_fence_enabled():
        fence_enabled = True
    fence_action = get_fence_action()
    fence_timeout = get_fence_timeout()
    return (fence_enabled, fence_action, fence_timeout)


def check_node_status(node, state):
    rc, stdout, stderr = run_cmd('crm_node -l')
    if rc != 0:
        msg_error(stderr)
        return False
    pattern = re.compile(r'^.* {} {}'.format(node, state), re.MULTILINE)
    if not pattern.search(stdout):
        return False
    return True


def do_fence_happen(node, run_time):
    rc, stdout, stderr = run_cmd('stonith_admin -h {}'.format(node))
    if rc != 0:
        msg_error(stderr)
        return False
    if re.search('Node {} last kicked at:'.format(node), stdout):
        kicked_time = stdout.split('at:')[1].strip()
        kicked_time_format = "%a %b %d %H:%M:%S %Y"
        return int(run_time) < \
               int(datetime.strptime(kicked_time, kicked_time_format).strftime("%s"))
    else:
        return False


def service_is_active(service):
    """
    Check if service is active
    """
    rc, _, _ = run_cmd('systemctl -q is-active {}'.format(service))
    return rc == 0


def is_cluster_running():
    return service_is_active('corosync') and \
           service_is_active('pacemaker')


def which(prog):
    rc, _, err = run_cmd("which {}".format(prog))
    if rc != 0:
        msg_error(err)
        return False
    return True
