

- Each session should be able to report the actions
- Each operation in the session should fail, and failure should either
  halt the session, or issue a warning. By default, it should halt on failure.
- In tracing mode, the session output is communicated back
- By default, only the errors are communicated back up


## Error reporting

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
