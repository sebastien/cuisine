# Connections

Cuisine uses shell commands as the main communication channel to interact
with (remote) systems. It does support different types of underlying transport,
primarily through SSH. While the basic requirement is to execute shell
commands, a connection should ideally support
uploading files to speed things up.

The basic contract of a channel is like so:

- `connect()/disconnect()` to open/close the connection
- `run()` to run a command

Then there are some additional features that can make it more efficient:

- `write(path,content)` to write binary content at the given path
- `upload(path,local)` to upload a file to the remote location
- `cd(path)` to change the current directory.

Here's an example:

```python
with cuisine.connect() as c:
  c.run("echo 'Hello, World!'")
```

## Default connection

By default, the connection is local and any command run using Cuisine's API
will be *local*, represented by the `local()` call of the API.  However, as
soon as `connect()` is used, the connection will be added to the *connection
stack* and will become the current active connection, which you can get using
`connection().`

## Multiple connections

You can manage multiple connections by referencing them and using them
as a prefix, as they all implement the core Cuisine API:

```python
# The latest `connect` sets the latest connection
server_a = connect("server-a.domain.local")
assert connection() == server_a
server_b = connect("server-b.domain.local")
assert connection() == server_b

# We can still access/interact with individual connections by referring
# to them directly.
assert server_a.hostname() == "server-a.domain.local"
assert server_b.hostname() == "server-b.domain.local"
assert hostname() == "server-b.domain.local"
```

## Transient connections

The `connect()` primitive can be used to create temporary connections
by using the `with` keyword.

```python
with connect("server.domain.local") as c:
  # The new connection will become the current connection
  assert connection() is c
# And as soon as we're out, the local connection becomes the current
# connection.
assert connection() is local()
```
