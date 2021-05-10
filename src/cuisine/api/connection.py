from cuisine.connection.paramiko import ParamikoConnection
from ..connection import CommandOutput, Connection
from ..connection.local import LocalConnection
from ..api import APIModule
from ..decorators import expose, dispatch, variant
from ..utils import prefix_command
from typing import Optional, ContextManager, Union, List
from pathlib import Path


class Connection(APIModule):
    """Manages connections to local and remote hosts."""

    def init(self):
        # We the default connection is local
        self.__connections: List[Connection] = [LocalConnection()]

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
    def connect(self, host=None, port=None, user=None, password=None, key: Union[str, Path] = None, transport: Optional[str] = None) -> Connection:
        """Connects to the given host/port using the given user/password/key_path credentials. Note that
        not all connection types support all these arguments, so you might get warnings if they are
        not supported."""
        print(host, port, user, password, key)
        transport = transport or self.api.detect_connection() if host or port else "local"
        if transport == "local":
            assert not user, "Local user change is not supported yet"
            return self.connection()
        else:
            connection_creator = getattr(self.api, f"connect_{transport}")
            if not connection_creator:
                raise RuntimeError(
                    f"Connection type not supported: {transport}")
            else:
                res = connection_creator(
                    host=host, port=port, user=user, password=password, key=key)
                self.__connections.append(res)
                res.on_disconnect = self.clean_connections
                res.connect()
                return res

    @expose
    def disconnect(self) -> Optional[Connection]:
        """Disconnects from the current connection unless it's the default
        local connection."""
        if len(self.__connections) > 1:
            conn = self._connections.pop()
            conn.disconnect()
            return conn
        else:
            return None

    @expose
    @variant("local")
    def connect_local(self) -> Connection:
        return LocalConnection()

    @expose
    @variant("paramiko")
    def connect_paramiko(self, host=None, port=None, user=None, password=None, key: Optional[Path] = None) -> Connection:
        return ParamikoConnection(host=host, port=port, user=user, password=password, key=key)

    @expose
    def run(self, command: str) -> 'CommandOutput':
        return self._connection.run(command)

    @ expose
    def run_local(self, command: str) -> 'CommandOutput':
        local_connection = self.__connections[0]
        assert isinstance(local_connection, LocalConnection)
        return local_connection.run(command)

    @ expose
    def sudo(self, command: str) -> 'CommandOutput':
        return self._connection.run(prefix_command(command, "sudo"))

    @ expose
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
