

processes_name_want_to_kill = [
    ('sbd', '', 'fence'),
    ('corosync', '', 'fence'),
    ('pacemakerd', '', 'restart'),
    ('pacemaker-based', 'cib', 'fence'),
    ('pacemaker-fenced', 'stonithd', 'restart'),
    ('pacemaker-execd', 'lrmd', 'restart'),
    ('pacemaker-attrd', 'attrd', 'restart'),
    ('pacemaker-schedulerd', 'pengine', 'restart'),
    ('pacemaker-controld', 'crmd', 'restart')
]


RESTART_TIMEOUT = 5
FENCE_TIMEOUT = 60
FENCE_SELF = "crm_attribute -t status -N '{}' -n terminate -v true"
FENCE_NODE = "stonith_admin -F '{}'"
LOGIN = False
LOGIN_USER = None
LOGIN_PASSWORD = None
PASS_ASK = False


class Option(object):
    def __init__(self, name, alias, expect):
        self.name = name
        self.alias = alias
        self.expect = expect
        self.command = "killall -9 " + self.name
        self.option = "--kill-{}".format(self.alias if self.alias else self.name)
        self.dest = self.alias if self.alias else self.name
        self.help = "kill {}{} daemon".\
                    format(self.name, "({})".format(self.alias) if self.alias else "")

    def __str__(self):
        return "name: {}\nalias: {}\ncommand: {}\noption: {}\nhelp: {}\n\n".\
               format(self.name, self.alias, self.command, self.option, self.help)


option_list = []
for item in processes_name_want_to_kill:
    if isinstance(item, tuple):
        option_list.append(Option(*item))
