from cuisine.connection.mitogen import MitogenConnection
c = MitogenConnection().connect("localhost")
assert c.run("echo 'Hello, World!'").value == "Hello, World!"
assert c.run("echo -n 'Hello, World!'").value == "Hello, World!"
print("OK")
print("END")
# EOF
