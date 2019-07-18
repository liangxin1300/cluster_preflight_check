from __future__ import print_function
import re
from . import utils


def check(context):
    '''
    Check environment and cluster state if related options enabled
    '''
    if context.env_check:
        check_environment()
    if context.cluster_check:
        check_cluster()
    print()


def check_environment():
    '''
    A set of functions to check environment
    '''
    print("\n============ Checking environment ============")
    check_my_hostname_resolves()
    check_time_service()
    check_watchdog()
    check_firewall()


def check_my_hostname_resolves():
    '''
    Check hostname resolvable
    '''
    task = utils.TaskCheck("Checking hostname resolvable")

    hostname = utils.this_node()
    try:
        import socket
        socket.gethostbyname(hostname)
    except socket.error:
        task.error('''Hostname "{}" is unresolvable.
         {}'''.format(hostname, "Please add an entry to /etc/hosts or configure DNS."))
    finally:
        task.print_result()


def check_time_service():
    '''
    Check time service
    '''
    task = utils.TaskCheck("Checking time service")

    timekeepers = ('chronyd.service', 'ntp.service', 'ntpd.service')
    timekeeper = None
    for tk in timekeepers:
        if utils.service_is_available(tk):
            timekeeper = tk
            break

    if timekeeper is None:
        task.warn("No NTP service found.")
    else:
        task.info("{} is available".format(timekeeper))
        if utils.service_is_enabled(timekeeper):
            task.info("{} is enabled".format(timekeeper))
        else:
            task.warn("{} is disabled".format(timekeeper))

        if utils.service_is_active(timekeeper):
            task.info("{} is active".format(timekeeper))
        else:
            task.warn("{} is not active".format(timekeeper))

    task.print_result()


def check_watchdog():
    '''
    Verify watchdog device. Fall back to /dev/watchdog.
    '''
    task = utils.TaskCheck("Checking watchdog")

    watchdog_dev = utils.detect_watchdog_device()
    rc, _, _ = utils.run_cmd('lsmod | egrep "(wd|dog)"')
    if rc != 0:
        task.warn("Watchdog device must be configured if want to use SBD!")
    task.print_result()


def check_port_open(task, item):
    '''
    Check whether corosync port is blocked by iptables
    '''
    ports = utils.corosync_port()
    if not ports:
        task.error("Can not get corosync's port")
        return

    if item == "firewalld":
        rc, out, err = utils.run_cmd('firewall-cmd --list-port')
        if rc != 0:
            task.error(err)
        for p in ports:
            if re.search(' {}/udp'.format(p), out):
                task.info("UDP port {} is opened in firewalld".format(p))
            else:
                task.error("UDP port {} should open in firewalld".format(p))
    if item == "SuSEfirewall2":
        #TODO
        pass


def check_firewall():
    '''
    Check firewall
    '''
    task = utils.TaskCheck("Checking firewall")

    for item in ("firewalld", "SuSEfirewall2"):
        if utils.package_is_installed(item):
            task.info("{}.service is available".format(item))
            if utils.service_is_active(item):
                task.info("{}.service is active".format(item))
                check_port_open(task, item)
            else:
                task.warn("{}.service is not active".format(item))
            break
    else:
       task.error("Failed to detect firewall")

    task.print_result()


def check_cluster():
    '''
    A set of functions to check cluster state
    '''
    print("\n============ Checking cluster state ============")
    if not check_cluster_service():
        return
    check_fencing()
    check_nodes()
    check_resources()


def check_cluster_service(quiet=False):
    '''
    Check service status of pacemaker/corosync
    '''
    task = utils.TaskCheck("Checking cluster service", quiet=quiet)
    for s in ("pacemaker", ):
        if utils.service_is_enabled(s):
            task.info("{} is enabled".format(s))
        else:
            task.warn("{} is disabled".format(s))

    for s in ("corosync", "pacemaker"):
        if utils.service_is_active(s):
            task.info("{} service is running".format(s))
        else:
            task.error("{} service is not running!".format(s))
    task.print_result()
    return task.passed


def check_fencing():
    '''
    Check STONITH/Fence:
      Whether stonith is enabled
      Whether stonith resource is configured and running
    '''
    task = utils.TaskCheck("Checking STONITH/Fence")

    if utils.fence_enabled():
        task.info("stonith-enabled is \"true\"")
    else:
        task.warn("stonith is disabled")

    use_sbd = False
    rc, outp, _ = utils.run_cmd("crm_mon -r1 | grep '(stonith:.*):'")
    if rc == 0:
        res = re.search(r'([^\s]+)\s+\(stonith:(.*)\):\s+(\w+)', outp)
        res_name, res_agent, res_state = res.groups()
        common_msg = "stonith resource {}({})".format(res_name, res_agent)
        state_msg = "{} is {}".format(common_msg, res_state)

        task.info("{} is configured".format(common_msg))
        if res_state == "Started":
            task.info(state_msg)
        else:
            task.warn(state_msg)

        if re.search(r'sbd$', res_agent):
            use_sbd = True
    else:
        task.warn("No stonith resource configured!")

    if use_sbd:
        if utils.service_is_active("sbd"):
            task.info("sbd service is running")
        else:
            task.warn("sbd service is not running!")

    task.print_result()


def check_nodes():
    '''
    Check nodes info:
      Current DC
      Quorum status
      Online/OFFLINE/UNCLEAN nodes
    '''
    task = utils.TaskCheck("Checking nodes")

    cmd_awk = """awk '$1=="Current"||$1=="Online:"||$1=="OFFLINE:"||$3=="UNCLEAN"{print $0}'"""
    cmd = r'crm_mon -r1 | {}'.format(cmd_awk)
    rc, outp, errp = utils.run_cmd(cmd)
    if rc == 0:
        # check DC
        res = re.search(r'Current DC: (.*) \(', outp)
        if res:
            task.info("DC node: {}".format(res.group(1)))

        # check quorum
        if re.search(r'partition with quorum', outp):
            task.info("Cluster have quorum")
        else:
            task.warn("Cluster lost quorum!")

        # check Online nodes
        res = re.search(r'Online:\s+(\[.*\])', outp)
        if res:
            task.info("Online nodes: {}".format(res.group(1)))

        # check OFFLINE nodes
        res = re.search(r'OFFLINE:\s+(\[.*\])', outp)
        if res:
            task.warn("OFFLINE nodes: {}".format(res.group(1)))

        # check UNCLEAN nodes
        for line in outp.split('\n'):
            res = re.search(r'Node (.*): UNCLEAN', line)
            if res:
                task.warn('Node {} is UNCLEAN!'.format(res.group(1)))
    else:
        task.error("run \"{}\" error: {}".format(cmd, errp))

    task.print_result()


def check_resources():
    '''
    Check number of Started/Stopped/FAILED resources
    '''
    task = utils.TaskCheck("Checking resources")

    awk_stop = """awk '$3=="Stopped"||$0~/FAILED/{print $0}' | wc -l"""
    awk_start = """awk '$3=="Started"{print $0}' | wc -l"""
    cmd_stop = "crm_mon -r1 | {}".format(awk_stop)
    cmd_start = "crm_mon -r1 | {}".format(awk_start)

    rc, outp, errp = utils.run_cmd(cmd_stop)
    if rc == 0:
        task.info("Stopped/FAILED resources: {}".format(outp))
    else:
        task.error("run \"{}\" error: {}".format(cmd_stop, errp))

    rc, outp, errp = utils.run_cmd(cmd_start)
    if rc == 0:
        task.info("Started resources: {}".format(outp))
    else:
        task.error("run \"{}\" error: {}".format(cmd_start, errp))

    task.print_result()
