import os
import sys
import mitogen


def run(cmd):
    os.system(cmd)

# TODO: We want to retrieve the value
@mitogen.main()
def main(router):
    context = router.ssh(hostname="localhost")
    # TODO: We need (stdout, stderr, exit)
    res = context.call(run, "echo 'Hello, World!'")
    print ("RES", res)

# EOF
