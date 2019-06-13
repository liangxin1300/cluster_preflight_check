
pacemaker2_daemons = ("pacemaker-based", "pacemaker-fenced", "pacemaker-execd",
                    "pacemaker-attrd", "pacemaker-schedulerd", "pacemaker-controld")


RESTART_TIMEOUT = 5
FENCE_TIMEOUT = 60
FENCE_NODE = "crm_attribute -t status -N '{}' -n terminate -v true"
BLOCK_PORT = "iptables -I INPUT -m state --state NEW -p udp --dport {} -j REJECT"
LOGIN = False
LOGIN_USER = None
LOGIN_PASSWORD = None
PASS_ASK = False
MASK = False
LOOP = False
DEBUG = False

