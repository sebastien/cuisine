# Connections

Cuisine is designed to have relatively dumb connections, where the primary
communication channel is through shell commands. Ideally, a connection supports
uploading files, but in case it does not, the uploading/downloading of files
is done by chunking the content and transferring it as text content.

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
