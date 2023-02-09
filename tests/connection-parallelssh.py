print("=== TEST ParallelSSH connection")
from cuisine.connection.parallelssh import ParallelSSHConnection

c = ParallelSSHConnection().connect("localhost")
assert c.run("echo 'Hello, World!'").value == "Hello, World!"
assert c.run("echo -n 'Hello, World!'").value == "Hello, World!"
print("<.. EOK")
# EOF
