from cuisine.connection.paramiko import ParamikoConnection
from ..connection import CommandOutput, Connection
from ..connection.local import LocalConnection
from ..api import APIModule
from ..decorators import expose, dispatch, variant
from ..utils import prefix_command
from typing import Optional
from pathlib import Path


class Connection(APIModule):
    """Manages connections to local and remote hosts."""

    def init(self):
        self.__connection: Optional[Connection] = None

    @property
    def _connection(self):
        if not self.__connection:
            self.__connection = LocalConnection()
        return self.__connection

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
    @dispatch("connection")
    def connect(self, host=None, port=None, user=None, password=None, key_path: Optional[Path] = None) -> Connection:
        """Connects to the given host/port using the given user/password/key_path credentials. Note that
        not all connection types support all these arguments, so you might get warnings if they are
        not supported."""

    @expose
    @variant("local")
    def connect_local(self) -> Connection:
        return LocalConnection()

    @expose
    @variant("paramiko")
    def connect_paramiko(self, host=None, port=None, user=None, password=None, key_path: Optional[Path] = None) -> Connection:
        return ParamikoConnection(host=host, port=port, user=user, password=password)

    @expose
    def run(self, command: str) -> 'CommandOutput':
        return self._connection.run(command)

    @expose
    def sudo(self, command: str) -> 'CommandOutput':
        return self._connection.run(prefix_command(command, "sudo"))


# EOF
