#!/usr/bin/env python
import sys
import paramiko

# SEE: With keys <https://gist.github.com/batok/2352501>
try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    # FIXME: Paramiko does not work out of the box there
    client.connect("localhost", username="spierre", look_for_keys=True)
    stdin, stdout, stderr = client.exec_command("echo 'Hello, World'")
    print (stdout.read())
finally:
    client.close()
