from cuisine import *


# To do this, you will need to 1) have an ssh server running on
# your current host, and 2) to have `parallel-ssh` installed.
connect(host="localhost", user=run_local(
    "whoami").last_line, transport="mitogen")
# This will now be run through the SSH connection
print("cuisine got:", run("echo 'Hello, World'!").value,
      f"through {connection().host} via {connection().type}")
# EOF
