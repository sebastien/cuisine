from cuisine.connection.paramiko import ParamikoConnection
from cuisine.connection.tmux import TmuxConnection
from ..connection import CommandOutput, Connection
from ..connection.local import LocalConnection
from ..api import APIModule
from ..decorators import expose, dispatch, variant
from ..utils import prefix_command
from typing import Optional, ContextManager, Union, List
from pathlib import Path


class ConnectionContext(ContextManager):
    """Automatically disconnects a connection path to where it was."""

    def __init__(self, connection: 'Connection'):
        self.connection = connection
        self.has_entered = False

    def __enter__(self):
        self.has_entered = True

    def __exit__(self, type, value, traceback):
        if self.has_entered:
            self.connection.disconnect()


class Connection(APIModule):
    """Manages connections to local and remote hosts."""

    def init(self):
        # We the default connection is local
        self.__connections: List[Connection] = [LocalConnection()]

    def register_connection(self, connection: Connection) -> ContextManager:
        """Registers the connection, connects it and returns a context
        manager that will disconnect from it on exit. This is an internal
        method used by the `connect_*` methods."""
        self.__connections.append(connection)
        connection.on_disconnect = lambda _: self.clean_connections(_)
        connection.connect()
        return ConnectionContext(connection)

    def clean_connections(self, connection: Optional[Connection] = None):
        """Cleans the connections, removing the ones that are disconnected"""
        if connection:
            self.__connections = [
                _ for _ in self.__connections if _ is not connection]
        else:
            self.__connections = [
                _ for _ in self.__connections if _.is_connected]

    @property
    def _connection(self) -> Connection:
        return self.__connections[-1]

    @expose
    def fail(self, message: Optional[str] = None):
        self._connection.log.error(f"Failure: {message}")

    @expose
    def connection(self) -> Connection:
        """Returns the current connection"""
        return self._connection

    @expose
    def is_local(self) -> bool:
        """Tells if the current connection is local or not."""
        return isinstance(self._connection, LocalConnection)

    @expose
    def detect_connection(self) -> str:
        """Detects the recommended type of connection"""
        return "paramiko"

    @expose
    def select_connection(self, type: str) -> bool:
        """Selects the default type of connection. This returns `False` in case
        the connection is not found."""
        return True

    @expose
    def connect(self, host=None, port=None, user=None, password=None, key: Union[str, Path] = None, transport: Optional[str] = None) -> ContextManager:
        """Connects to the given host/port using the given user/password/key_path credentials. Note that
        not all connection types support all these arguments, so you might get warnings if they are
        not supported."""
        print(host, port, user, password, key)
        transport = transport or self.api.detect_connection() if host or port else "local"
        if transport == "local":
            assert not user, "Local user change is not supported yet"
            return ConnectionContext(self.connection())
        else:
            connection_creator = getattr(self.api, f"connect_{transport}")
            if not connection_creator:
                raise RuntimeError(
                    f"Connection type not supported: {transport}")
            else:
                return connection_creator(
                    host=host, port=port, user=user, password=password, key=key)

    @expose
    def disconnect(self) -> Optional[Connection]:
        """Disconnects from the current connection unless it'"s the default
        local connection."""
        if len(self.__connections) > 1:
            conn = self.__connections.pop()
            conn.disconnect()
            return conn
        else:
            return None

    @expose
    @variant("local")
    def connect_local(self) -> ContextManager:
        return self.register_connection(LocalConnection())

    @expose
    @variant("paramiko")
    def connect_paramiko(self, host=None, port=None, user=None, password=None, key: Optional[Path] = None) -> ContextManager:
        return self.register_connection(ParamikoConnection(host=host, port=port, user=user, password=password, key=key))

    @expose
    def connect_tmux(self, session: str, window: str) -> ContextManager:
        """Creates a new connection using the TmuxConnection"""
        return self.register_connection(TmuxConnection(self._connection, session, window))

    @expose
    def run(self, command: str) -> 'CommandOutput':
        return self._connection.run(command)

    @expose
    def run_local(self, command: str) -> 'CommandOutput':
        local_connection = self.__connections[0]
        assert isinstance(local_connection, LocalConnection)
        return local_connection.run(command)

    @expose
    def sudo(self, command: str) -> 'CommandOutput':
        return self._connection.run(prefix_command(command, "sudo"))

    @expose
    def cd(self, path: str) -> ContextManager:
        """Changes the current connection path, returning a context that can be
        used like so:

        ```python
        cd("~")
        with cd("/etc"):
            run("ls -l")
        # Current path will be "~"
        ```
        """
        return self._connection.cd(path)

# EOF
