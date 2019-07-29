# cluster-preflight-check
Tool for Standardize Testing of Basic Cluster Functionality

## Features
#### Check environment
* check hostname resolvable
* check time service
* check watchdog
* check firewall
#### Check cluster state
* check cluster service
* check STONITH/Fence configuration
* check nodes
* check resources
#### Killing test cases
* kill sbd daemon
* kill corosync daemon
* kill pacemakerd daemon

When running killing test case, a report will be created at /var/lib/cluster-preflight-check;<br>
Report will includes test case description, action logging and explanation for possible results.
#### Fence specific node
#### Make split brain
#### Others
* JSON results for each test case
* Python2.7 and Python3.4+ support
* Tested in SLE12sp3, SLE12sp4 and SLE15sp1

## Install
pip install cluster-preflight-check

## Use
cluster-preflight-check --help
```
usage: cluster-preflight-check [-e] [-c]
                               [--kill-sbd | --kill-corosync | --kill-pacemakerd | --fence-node NODE | --split-brain-iptables]
                               [-l] [-y] [-h]

Cluster preflight check tool set

optional arguments:
  -e, --env-check         Check environment
  -c, --cluster-check     Check cluster state
  --kill-sbd              Kill sbd daemon
  --kill-corosync         Kill corosync daemon
  --kill-pacemakerd       Kill pacemakerd daemon
  --fence-node NODE       Fence specific node
  --split-brain-iptables  Make split brain by blocking corosync ports
  -l, --kill-loop         Kill process in loop

other options:
  -y, --yes               Answer "yes" if asked to run the test
  -h, --help              show this help message and exit

Log: /var/log/cluster-preflight-check.log
Json results: /var/lib/cluster-preflight-check/cluster-preflight-check.json
For each --kill-* testcase, report directory: /var/lib/cluster-preflight-check
```



## Demo
https://asciinema.org/a/248538
