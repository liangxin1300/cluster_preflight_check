
pacemaker2_daemons = ("pacemaker-based", "pacemaker-fenced", "pacemaker-execd",
                    "pacemaker-attrd", "pacemaker-schedulerd", "pacemaker-controld")

expected_resources = {
    'sbd':        ('Restart|Fenced', 'Fenced'),
    'corosync':   ('Restart|Fenced', 'Fenced'),
    'pacemakerd': ('Restart', None),
}


RESTART_TIMEOUT = 5
FENCE_TIMEOUT = 60
FENCE_NODE = "crm_attribute -t status -N '{}' -n terminate -v true"
#FENCE_NODE = "stonith_admin -F '{}'"
LOGIN = False
LOGIN_USER = None
LOGIN_PASSWORD = None
PASS_ASK = False
MASK = False
LOOP = False
DEBUG = False


class Option(object):
    def __init__(self, name, alias, expect, systemd):
        from . import utils
        if utils.is_pacemaker_1() and alias != '':
            self.name = alias
        else:
            self.name = name
        self.alias = alias
        self.expect = expect
        self.mask_cmd = "systemctl mask {} --runtime".format(systemd)
        self.unmask_cmd = "systemctl unmask {} --runtime".format(systemd)
        # killall doesn't work for long command, see man killall
        if len(self.name) > 15:
            self.command = "kill -9 `pidof {}`".format(self.name)
        else:
            self.command = "killall -9 " + self.name
        self.option = "--kill-{}".format(self.alias if self.alias else self.name)
        self.dest = self.alias if self.alias else self.name
        self.help = "kill {}{} daemon".\
                    format(self.name, "({})".format(self.alias) if self.alias else "")

    def __str__(self):
        return "name: {}\nalias: {}\ncommand: {}\noption: {}\nhelp: {}\n\n".\
               format(self.name, self.alias, self.command, self.option, self.help)

