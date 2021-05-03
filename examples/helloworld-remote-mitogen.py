from cuisine import *


select_transport("mitogen")
# To do this, you will need to 1) have an ssh server running on
# your current host, and 2) to have `parallel-ssh` installed.
connect(host="localhost", user=run_local("whoami").last_line)
# This will now be run through the SSH connection
run("echo 'Hello, World'!")

