from pathlib import Path
import os
from typing import Optional, Tuple, Any, List, Iterable, Union, ContextManager
from ..utils import shell_safe, strip_ansi, prefix_command
from .. import logging

# =============================================================================
#
# COMMAND OUTPUT
#
# =============================================================================


class CommandOutput(str):
    """Wraps the result of a command output, this is the standard object
    that you will be getting as a result of running commands. It has
    the following fields:

    - `out`, the output stream
    - `err`, the output stream
    - `status`, the command status
    - `command`, the original command
    """

    STATUS_SUCCESS = (0,)

    # I'm not sure how that even works, as we're not initializing self with
    # `out`, but it still does work.
    def __init__(self, res: Tuple[str, int, bytes, bytes]):
        str.__init__(self)
        command, status, out, err = res
        self.command = command
        self.status = status
        self._out = out
        self._err = err
        self._outStr: Optional[str] = None
        self._errStr: Optional[str] = None
        self.encoding = "utf8"
        self._value: Any = None

    @property
    def out(self) -> str:
        if self._outStr is None:
            self._outStr = str(self._out, self.encoding)
        return self._outStr

    @property
    def out_nocolor(self) -> str:
        return strip_ansi(self.out)

    @property
    def err(self) -> str:
        if self._errStr is None:
            self._errStr = str(self._err, self.encoding)
        return self._errStr

    @property
    def err_nocolor(self) -> str:
        return strip_ansi(self.err)

    @property
    def out_bytes(self) -> bytes:
        return self._out

    @property
    def err_bytes(self) -> bytes:
        return self._err

    @property
    def check_value(self) -> Any:
        if not self.is_success:
            raise RuntimeError(
                f"Command failed with status {self.status}: {self.command}")
        else:
            return self.value

    @property
    def value(self) -> Any:
        if self._value is None:
            self._value = self.last_line
        return self._value

    @property
    def lines(self) -> Iterable[str]:
        return self.out.split("\n")

    @property
    def has_value(self) -> bool:
        return bool(self.value)

    @property
    def last_line(self) -> str:
        """Returns the last line, stripping the trailing EOL"""
        i = self.out.rfind("\n", 0, -2)
        return (self.out if i == -1 else self.out[i+1:]).rstrip("\n")

    @property
    def is_success(self) -> bool:
        """Returns true if the command status is one of `STATUS_SUCCESS`"""
        return self.status in self.STATUS_SUCCESS

    @property
    def has_failed(self) -> bool:
        return not self.is_success

    def __str__(self) -> str:
        # FIXME: This might not be OK for all commands
        return str(self.last_line)

    def __repr__(self) -> str:
        return f"Command: {self.command}\nstatus: {self.status}\nout: {repr(logging.stringify(self.out))}\nerr: {repr(logging.stringify(self.err))}"

# =============================================================================
#
# CURRENT PATH
#
# =============================================================================


class CurrentPathContext(ContextManager):
    """A helper object returned by `cd` that will return the connection's
    path to where it was."""

    def __init__(self, connection: 'Connection', path: Optional[str] = None):
        """On exit, the given connection will be cd'ed to the given path. If no path
        is given ,then the connection's current path will be used."""
        self.path = path or connection.path
        self.connection = connection

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        # We don't do anything recursive
        if self.path and self.connection.path != self.path:
            self.connection._cd(self.path)


class SudoContext(ContextManager):
    """A helper object that will temporarily set the connection to sudo."""

    def __init__(self, connection: 'Connection'):
        self.is_sudo = connection.is_sudo
        self.connection = connection

    def __enter__(self):
        self.connection.is_sudo = True

    def __exit__(self, type, value, traceback):
        self.connection.is_sudo = self.is_sudo

# =============================================================================
#
# CONNECTION
#
# =============================================================================


class Connection:
    """Abstract implementation of a remote SSH connection. Connections are
    created with credentials, and then we can connect to and disconnect from
    the connections. Commands can be run as strings, and return
    a `CommandOutput` object."""

    TYPE = "unknown"

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, user: Optional[str] = None, password: Optional[str] = None, key: Optional[Path] = None):
        self.key = Path(os.path.normpath(os.path.expanduser(
            os.path.expandvars(key)))) if key else None
        self.password: Optional[str] = password
        self.user: Optional[str] = user
        self.host: Optional[str] = host
        self.port: Optional[int] = port
        self.timeout: int = 5
        self.is_sudo = False
        self.is_connected = False
        self.type = self.TYPE
        self._path: Optional[str] = None
        self.cd_prefix: str = ""
        self.log = logging.Context()
        self.log.prompt = self.prompt
        self.on_disconnect = None
        self.init()

    def init(self):
        pass

    def prompt(self):
        res: List[str] = []
        if self.type:
            res.append(f"{self.type}://")
        if self.user:
            res.append(f"{self.user}@")
        if self.host:
            res.append(self.host)
        if self.port:
            res.append(f":{self.port}")
        if self.path:
            res.append(f":{self.path}")
        return "".join(res)

    @property
    def path(self) -> Optional[str]:
        return self._path

    @path.setter
    def path(self, value: str):
        self._path = value
        # We store the cd_prefix as we need to prefix commands with
        # a directory.
        self.cd_prefix = f"cd '{shell_safe(value)}';"if value else ""

    def connect(self, host: Optional[str] = None, port: Optional[int] = None, user: Optional[str] = None, password: Optional[str] = None, key: Optional[Path] = None):
        assert not self.is_connected, "Connection already made, call 'disconnect' first"
        self.host = host or self.host
        self.port = port or self.port
        self.user = user or self.user
        self.password = password or self.password
        self.key = password or self.key
        self.log.action("connect")
        self._connect()
        return self

    def reconnect(self, user: Optional[str], host: Optional[str], port: Optional[int]) -> 'Connection':
        self.disconnect()
        self.user = user or self.user
        host = host or self.host or "localhost"
        port = port or self.port or 22
        self.log.action("reconnect")
        return self.connect(host, port)

    def run(self, command: str) -> Optional[CommandOutput]:
        if self.is_sudo:
            return self.sudo(command)
        else:
            self.log.action("command", command)
            res = self._run(command)
            self.log.result(res.value if res else None, res.is_success)
            return res

    def sudo(self, command: Optional[str] = None) -> Union[ContextManager, Optional[CommandOutput]]:
        if not command:
            return SudoContext(self)
        else:
            self.log.action("command.sudo", command)
            res = self._sudo(command)
            self.log.result(res.value if res else None, res.is_success)
            return res

    def cd(self, path: str) -> CurrentPathContext:
        context = CurrentPathContext(self, self.path)
        self.path = path
        self._cd(path)
        return context

    def upload(self, remote: str, local: str) -> bool:
        """Copies from the local file to the remote path"""
        self.log.action("upload", remote, local)
        local_path = Path(os.path.normpath(
            os.path.expanduser(os.path.expandvars(local))))
        if not local_path.exists():
            raise ValueError(f"Local path does not exists: '{local}'")
        self._upload(remote, local_path)
        return True

    def write(self, remote: str, content: bytes) -> bool:
        self.log.action("write", remote, str(len(content)))
        return self._write(remote, content)

    def disconnect(self) -> bool:
        self.log.action("disconnect")
        self._disconnect()
        if self.on_disconnect:
            self.on_disconnect(self)
        return self.is_connected

    def _connect(self):
        raise NotImplementedError

    def _disconnect(self):
        raise NotImplementedError

    def _write(self, path: str, content: bytes):
        raise NotImplementedError

    # FIXME: Arg #1 should be command
    def _run(self, path: str) -> Optional[CommandOutput]:
        raise NotImplementedError

    def _sudo(self, command: str) -> Optional[CommandOutput]:
        return self._run(prefix_command(command, "sudo"))

    def _upload(self, remote: str, source: Path):
        with open(source, "rb") as f:
            self._write(remote, f.read())

    def _cd(self, path: str):
        raise NotImplementedError

# EOF
