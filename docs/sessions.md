# Sessions

Sessions are high-level connections that make it easier to interact
with the host.

```python
with session() as s:
  print (s.echo("Hello, World"))
  with s.open("/etc/users", "r") as f:
    print (f.read())
```

Sessions provide primitive commands:

- `open(path)` to open files for read/write
- `cd(path)` to change the directory
- `exec(command, *args)` to run a given command
- `conf` is the session configuration
- `env` is the session environment

and any attribute that is not part of that will be resolved as a command,
using the following process:

- Is the command found in the session configuration? Then the configuration
  value will be used.
- Is the command found in the session environment as `COMMAND_{COMMAND:upper}`? Then the value
  value will be used.
- Otherwise the command name will be used as-is
