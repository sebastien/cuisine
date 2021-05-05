# Persistent Sessions

Cuisine can run commands by layering connections. For instance, you can
interact with a local screen sessions:

```python
# Local screen connection
with connect_screen("my-session") as s:
  print(s.run("Hello, from $(hostname)"))
# Remote screen connection
with connect("my-remote-host") as c:
  with c.connect_screen("my-session") as s:
    print(s.run("Hello, from $(hostname)"))

```

When connecting to persistent sessions, you'll need to make sure that
the corresponding commands are available on the remote host, for instance
by doing `package_ensure("screen")`.

## Screen

`connect_screen`

## Tmux

`connect_tmux`

## Mosh

`connect_mosh`
