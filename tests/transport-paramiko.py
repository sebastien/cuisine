#!/usr/bin/env python
import sys
import paramiko

# SEE: With keys <https://gist.github.com/batok/2352501>
try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    # FIXME: Paramiko does not work out of the box there
    client.connect(hostname="127.0.0.1", username="spierre", look_for_keys=True, key_filename="/home/spierre/.ssh/id_rsa.pub")
    stdin, stdout, stderr = client.exec_command("echo 'Hello, World'")
    print (stdout.read())
finally:
    client.close()
