# clusterTestTool
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

When running killing test case, a report will be created at /var/lib/cluster-test-tool;<br>
Report will includes test case description, action logging and explanation for possible results.
#### Fence specific node
#### Make split brain
#### Others
* JSON results for each test case
* Python2.7 and Python3.4+ support
* Tested in SLE12sp3, SLE12sp4 and SLE15sp1

## Install
pip install cluster-test-tool

## Use
cluster-test-tool --help
```
usage: cluster-test-tool [-e] [-c]
                         [--kill-sbd | --kill-corosync | --kill-pacemakerd | --fence-node NODE | --split-brain-iptables]
                         [-l] [-y] [-h]

Cluster Testing Tool Set

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

Log: /var/log/cluster-test-tool.log
Json results: /var/lib/cluster-test-tool/cluster-test-tool.json
For each --kill-* testcase, report directory: /var/lib/cluster-test-tool
```



## Demo
https://asciinema.org/a/248538
