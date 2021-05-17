from ..api import APIModule
from ..decorators import expose
from typing import Optional
import os


class Environment(APIModule):
    """Manages connections to local and remote hosts."""

    @expose
    def env_get(self, variable: str, default: Optional[str] = None) -> str:
        """Returns the given `variable` from the connection's environment, returning
        `default` if not found."""
        return os.environ[variable] if variable in os.environ else default or ""

    @expose
    def env_set(self, variable: str, value: str) -> str:
        """Sets the given `variable` in the connection's environment, returning
        `default` if not found."""
        previous = self.env_get(variable)
        os.environ[variable] = value
        return previous

    @expose
    def env_clear(self, variable: str) -> str:
        """Clears the given `variable` from connection's environment.
        `default` if not found."""
        raise NotImplementedError

# EOF
