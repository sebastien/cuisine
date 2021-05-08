from cuisine.connection.local import LocalConnection
c = LocalConnection().connect()
assert c.run("echo 'Hello, World!'").value == "Hello, World!"
assert c.run("echo -n 'Hello, World!'").value == "Hello, World!"
print("OK")
print("END")
# EOF
