print("=== TEST ParamikoConnection connection")
from cuisine.connection.paramiko import ParamikoConnection

c = ParamikoConnection().connect("localhost")
assert c.run("echo 'Hello, World!'").value == "Hello, World!"
assert c.run("echo -n 'Hello, World!'").value == "Hello, World!"
print("<.. EOK")
# EOF
