# Reporting

Cuisine's reporting is designed for full observability of the process, supporting
the following:

- Each session should be able to report the actions (command run, output, errors)
- Each operation in the session should detect failures, and failure should either
  halt the session, or issue a warning. By default, it should halt on failure.
- In tracing mode, the session output is communicated back
- By default, only the errors are communicated back up

## Error handling

Cuisine by default won't stop when there is a command error, but will stop
in the following cases:

- A connection error, in which case an exception will be raised.

```
with mode_strict():
    # Any error in the commands will stop the current session
```
## Error reporting


Errors are reported in a way that is both easy to read (for humans), and
where structured data can be easily extracted when automating cuisine from
the CLI.

```python
run("tar fxz package.tar.gz")
```

will yield the following:

```
⫼	/bin/sh: line 1: cd: /home/service/dist: No such file or directory
⫼	tar (child): package.tar.gz: Cannot open: No such file or directory
⫼	tar (child): Error is not recoverable: exiting now
⫼	tar: Child returned status 2
⫼	tar: Error is not recoverable: exiting now
```


## Trace reporting

The `enable_trace()`,  `disable_trace()` and `with tracing()` functions all
support granular tracing, which can also be defined using the `CUISINE_TRACING`
environment variable.

```python
enable_trace()
run("du -hs /etc")
```

will return the command, input, output and err:

```
TRA user@localhost[local]
    command: du -hs /etc
    err: asdasdsa
    err: …
    out: asdasdsa
```
