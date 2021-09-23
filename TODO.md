  - File: when using file\_write, it seems that the existing attributes
    are not always preserved
:

- Commands run through API functions should be silenced unless we're debugging.
  Basically, we need some kind of command tracing.

- Have the command status as one line (single reporting), or like it is now (multiplexing)

- We need the multiplexing support

- Tmux sessions are nested within the same connection, and we need to have
  some kind of stateful part so that we absorb the detail by default. It's
  an interesting use case for logging.

Connection:
 - Automatically clears paramiko.ssh_exception.BadHostKeyException: Host key for server '3.104.147.76' does not match: got 'AAAAC3NzaC1lZDI1NTE5AAAAIFekt+4ctGPiY4PKB3V5okAOSdwRfHBfOmiYrX5/I8lk', expected 'AAAAC3NzaC1lZDI1NTE5AAAAIKAoGchYME9rbBRTfwq1upldReXfh7oAiLa4BgBBem5n'
