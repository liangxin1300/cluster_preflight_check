
pacemaker2_daemons = ("pacemaker-based", "pacemaker-fenced", "pacemaker-execd",
                    "pacemaker-attrd", "pacemaker-schedulerd", "pacemaker-controld")


RESTART_TIMEOUT = 5
FENCE_TIMEOUT = 60
FENCE_NODE = "crm_attribute -t status -N '{}' -n terminate -v true"
BLOCK_PORT = '''iptables -I INPUT -p udp --dport {port} -j REJECT;
                iptables -I OUTPUT -p udp --sport {port} -j REJECT'''
REMOVE_PORT = "firewall-cmd --zone=public --remove-port={port}/udp"
ADD_PORT = "firewall-cmd --zone=public --add-port={port}/udp"
FENCE_HISTORY = "stonith_admin --history={node}"
LOGIN = False
LOGIN_USER = None
LOGIN_PASSWORD = None
PASS_ASK = False
MASK = False
LOOP = False
DEBUG = False

