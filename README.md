# cluster-preflight-check
Tool for Standardize Testing of Basic Cluster Functionality

## Motivation
#### Convenient
Customers using tools like yast2-cluster/ha-cluster-bootstrap to setup a cluster.
Before really pushing into production environment, it's necessary to make sure everything in cluster works well and is configured correctly.
To archive above target, a lots of commands or steps will be included, like kill the primary process, check node/resource/cluster status, fence specific node,
simulate split brain scenarios, show these commands' results and how to recover.</br>
**So it will be more convenient if we can integrate these commands into one tool.**

#### Standard
**Ship the standard commands.**</br>
Like how to kill process, how to check status, how to make split brain, there are lots ways to to that. 
In the cluster-preflight-check, we only provide one way to do this, the way we make sure it do works and is recoverable. 

#### Reusable 
**Results can be reused.**</br>
cluster-preflight-check generates JSON result after each test case.
The JSON result includes loggings, descriptions, timestamp, and whether this case has passed.
It can easily be utilized by other tools/applications and be friendly with developer.

#### Traceable
**Process can be traceable.**</br>
cluster-preflight-check has loggings and reports.
For killing testcase, a report will be created.
Report will includes test case description, action logging and explanation for possible results.

#### Recoverable
cluster-preflight-check will not bring new troubles or unrecoverable troubles after executing actions.

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

When running killing test case, a report will be created at /var/lib/ha-cluster-preflight-check;<br>
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
ha-cluster-preflight-check --help
```
usage: ha-cluster-preflight-check [-e] [-c]
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

Log: /var/log/ha-cluster-preflight-check.log
Json results: /var/lib/ha-cluster-preflight-check/ha-cluster-preflight-check.json
For each --kill-* testcase, report directory: /var/lib/ha-cluster-preflight-check
```



## Demo
1. [using cluster-preflight-check to check environment and cluster status](https://asciinema.org/a/273850)
2. [using cluster-preflight-check to kill sbd process](https://asciinema.org/a/273851)
3. [using cluster-preflight-check to kill corosync process](https://asciinema.org/a/273852)
4. [using cluster-preflight-check to fence specific node](https://asciinema.org/a/273853)
5. [using cluster-preflight-check to simulate split brain](https://asciinema.org/a/273854)
