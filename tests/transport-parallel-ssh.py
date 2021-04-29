from pssh.clients import SSHClient
from datetime import datetime

host = 'localhost'
cmds = ['echo first command',
        'echo second command',
        'sleep 1; echo third command took one second',
        ]
# FIXME: This does not work either
client = SSHClient(host,pkey="~/.ssh/id_rsa")

start = datetime.now()
for cmd in cmds:
    out = client.run_command(cmd)
    for line in out.stdout:
        print(line)
end = datetime.now()
print("Took %s seconds" % (end - start).total_seconds())
