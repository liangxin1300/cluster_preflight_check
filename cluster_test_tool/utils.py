import subprocess
import os
import re
import time
import socket
import json
import logging
from datetime import datetime


CRED = '\033[31m'
CYELLOW = '\033[33m'
CGREEN = '\033[32m'
CEND = '\033[0m'


def me():
    return socket.gethostname()


def now(form="%Y/%m/%d %H:%M:%S"):
    return datetime.now().strftime(form)


def msg_str(msg_type, msg, timestamp=None, prefix=''):
    if msg_type not in ("info", "warn", "error", "debug"):
        raise TypeError("msg_type must be info|warn|error|debug")

    color = CGREEN
    if msg_type == "warn":
        color = CYELLOW
    if msg_type == "error":
        color = CRED
    if timestamp:
        prefix += "[{}]".format(timestamp)
    return "{}{}{}:{} {}".format(prefix, color, msg_type.upper(), CEND, msg)
 

def msg_info(msg):
    print(msg_str("info", msg, timestamp=now()))


def msg_warn(msg):
    print(msg_str("warn", msg, timestamp=now()))


def msg_error(msg):
    print(msg_str("error", msg, timestamp=now()))


def msg_debug(msg):
    from . import main
    if main.ctx.debug:
        print(msg_str("debug", msg))


def json_dumps():
    from . import main
    with open(main.ctx.jsonfile, 'w') as f:
        f.write(json.dumps(main.ctx.tasks, indent=2))


class Task(object):

    def __init__(self, description, flush=False):
        self.passed = True
        self.messages = []
        self.timestamp = now()
        self.description = description
        logging.info(description)
        self.flush = flush
        from . import main
        self.prev_tasks = main.ctx.tasks

    def info_append(self, msg):
        self.msg_append("info", msg)
        logging.info(msg)

    def warn_append(self, msg):
        self.msg_append("warn", msg)
        logging.warning(msg)

    def error_append(self, msg):
        self.msg_append("error", msg)
        logging.error(msg)

    def msg_append(self, msg_type, msg):
        if msg_type in ("warn", "error"):
            self.passed = False
        self.messages.append((msg_type, msg, now()))
        if self.flush:
            print(msg_str(msg_type, msg, now()))
            self.to_json()
            self.to_report()

    def build_base_result(self):
        self.result = {
            "Timestamp": self.timestamp,
            "Description": self.description,
            "Messages": ["{} {}:{}".format(m[2], m[0].upper(), m[1])
                         for m in self.messages]
        }


class TaskCheck(Task):

    def to_stdout(self):
        print(msg_str("info", self.description, self.timestamp), end=' ')
        if self.passed:
            print("[{}]".format(CGREEN + "Pass" + CEND))
        else:
            print("[{}]".format(CRED + "Fail" + CEND))
        
        for msg in self.messages:
            print(msg_str(msg[0], msg[1], prefix='  '))

    def to_json(self):
        self.build_base_result()
        self.result['Result'] = self.passed
        from . import main
        main.ctx.tasks.append(self.result)
        json_dumps()

    def print_result(self):
        self.to_stdout()
        self.to_json()

    def to_report(self):
        pass


class TaskKill(Task):

    def  __init__(self, description, name, expected, looping):
        super(self.__class__, self).__init__(description, flush=True)
        self.name = name
        self.expected = expected
        self.looping = looping
        self.report = False

    def enable_report(self):
        self.report = True
        from . import main
        if not os.path.isdir(main.ctx.report_path):
            msg_error("{} is not a directory".format(main.ctx.report_path))

        report_path = main.ctx.report_path
        report_name = "{}-{}.report".format(main.ctx.name, now("%Y%m%d_%H-%M-%S"))
        self.report_file = os.path.join(report_path, report_name)
        print("(Report: {})".format(self.report_file))

        if self.looping:
            content_key = "{}-l".format(self.name)
        else:
            content_key = self.name

        from . import explain
        _, nodes, _ = run_cmd("crm_node -l|awk '{print $2}'")
        n_list = [n for n in nodes.split('\n') if n != me()]
        self.explain = explain.contents[content_key].format(nodeA=me(), nodeB=n_list[0])

    def header(self):
        h = '''==============================================
Testcase:          {}
Looping Kill:      {}
Expected State:    {}
'''.format(self.description, self.looping, self.expected)
        return h

    def to_json(self):
        self.build_base_result()
        self.result['Looping Kill'] = self.looping
        self.result['Expected State'] = self.expected
        from . import main
        main.ctx.tasks = self.prev_tasks + [self.result]
        json_dumps()

    def to_report(self):
        if not self.report:
            return
        with open(self.report_file, 'w') as f:
            f.write(self.header())
            f.write("\nLog:\n")
            for m in self.messages:
                f.write("{} {}:{}\n".format(m[2], m[0].upper(), m[1]))
            f.write("\nTestcase Explained:\n")
            f.write("{}\n".format(self.explain))


class TaskFence(Task):

    def  __init__(self, description, fence_action, fence_timeout):
        super(self.__class__, self).__init__(description, flush=True)
        self.fence_action = fence_action
        self.fence_timeout = fence_timeout

    def header(self):
        h = '''==============================================
Testcase:          {}
Fence action:      {}
Fence timeout:     {}
'''.format(self.description, self.fence_action, self.fence_timeout)
        return h

    def to_json(self):
        self.build_base_result()
        self.result['Fence action'] = self.fence_action
        self.result['Fence timeout'] = self.fence_timeout
        from . import main
        main.ctx.tasks = self.prev_tasks + [self.result]
        json_dumps()

    def to_report(self):
        pass


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
        return s


def ask(msg):
    from . import main
    if main.ctx.yes:
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


def whether_pacemaker2_daemons():
    from . import config
    for daemon in config.pacemaker2_daemons:
        if not os.path.exists(os.path.join("/usr/lib/pacemaker", daemon)):
            return False
    return True


def is_pacemaker_1():
    return not whether_pacemaker2_daemons()


def detect_watchdog_device():
    """
    Find the watchdog device. Fall back to /dev/watchdog.
    """
    wdconf = "/etc/modules-load.d/watchdog.conf"
    watchdog_dev = "/dev/watchdog"
    if os.path.exists(wdconf):
        txt = open(wdconf, "r").read()
        for line in txt.splitlines():
            m = re.match(r'^\s*watchdog-device\s*=\s*(.*)$', line)
            if m:
                watchdog_dev = m.group(1)
    return watchdog_dev


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
            if procname == s or procname == s + ':':
                return True, pid
        except EnvironmentError:
            # a process may have died since we got the list of pids
            pass
    return False, -1


def get_property(name):
    cmd = "crm configure get_property " + name
    rc, stdout, _ = run_cmd(cmd)
    if rc != 0:
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


def fence_enabled():
    fence_enabled = get_property('stonith-enabled')
    return fence_enabled and fence_enabled.lower() == "true"


def get_fence_timeout():
    fence_timeout = get_property('stonith-timeout')
    if fence_timeout is None:
        return None
    if re.match('[0-9]+(s|)$', fence_timeout):
        return fence_timeout.strip('s')
    else:
        return None


def get_fence_info():
    enabled = True if fence_enabled() else False
    action = get_fence_action()
    timeout = get_fence_timeout()
    return (enabled, action, timeout)


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


def service_is_enabled(service):
    """
    Check if service is enabled
    """
    rc, _, _ = run_cmd('systemctl is-enabled {}'.format(service))
    return rc == 0


def grep_output(cmd, txt):
    _rc, outp, _err = run_cmd(cmd)
    return txt in outp


def service_is_available(svcname):
    return grep_output("systemctl list-unit-files {}".format(svcname), svcname)


def is_cluster_running():
    return service_is_active('corosync') and \
           service_is_active('pacemaker')


def which(prog):
    rc, _, err = run_cmd("which {}".format(prog))
    if rc != 0:
        msg_error(err)
        return False
    return True


def this_node():
    'returns name of this node (hostname)'
    return os.uname()[1]


def anyone_kill(node, task, timeout=100):
    count = 0
    while count < int(timeout):
        rc, out, _ = run_cmd("crm_mon -1|grep \"^Online:.* {} \"".format(node))
        if rc == 0:
            msg_debug("Node \"{}\" is online".format(node))
            break

        rc, out, _ = run_cmd("crm_mon -1|grep -A1 \"Fencing Actions:\"")
        if rc == 0:
            match = re.search(r"of (.*) pending: .*origin=(.*)$", out)
            if match.group(1) == node:
                task.info_append("Node \"{}\" will be fenced by \"{}\"!".format(match.group(1), match.group(2)))
                break

        time.sleep(0.1)
        count += 1
