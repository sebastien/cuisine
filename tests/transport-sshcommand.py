#!/usr/bin/env python

import subprocess
import getpass
from typing import List

# FROM: https://acrisel.github.io/posts/2017/08/ssh-made-easy-using-python/


def run_ssh(command: List[str], host="localhost", user=getpass.getuser(), port=22, stdin=None, check=False):
    result = subprocess.run(["ssh", f"{user}@{host}"] + [_ for _ in command],
                            shell=False,
                            stdin=stdin,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=check)
    return (result.stdout, result.stderr)


# SEE: With keys <https://gist.github.com/batok/2352501>
stdout, stderr = run_ssh(["echo", "Hello, World!"])
print(stdout, stderr)
