from ..connection import CommandOutput, Connection
from ..connection.local import LocalConnection
from ..api import APIModule
from ..decorators import expose
from typing import Optional


class Connection(APIModule):

    def init(self):
        self.__connection: Optional[Connection] = None

    @property
    def _connection(self):
        if not self.__connection:
            self.__connection = LocalConnection()
        return self.__connection

    @expose
    def run(self, command: str) -> 'CommandOutput':
        return self._connection.run(command)

# EOF
