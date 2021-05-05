

- Each session should be able to report the actions
- Each operation in the session should fail, and failure should either
  halt the session, or issue a warning. By default, it should halt on failure.
- In tracing mode, the session output is communicated back
- By default, only the errors are communicated back up


## Error reporting

Errors are reported in a way that is both easy to read (for humans), and
where structured data can be easily extracted when automating cuisine from
the CLI.

```python
run("tar fxz package.tar.gz")
```

will yield the following:

```
ERR user@localhost[local]: tar fxz package.tar.gz
    command: 'tar fxz package.tar.gz'
    error: 'Cannot open: No such file or directory'
    status: 2
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
