from cuisine.api import APIModule
from typing import Optional, Union
from ..decorators import expose
import os
import re

RE_INT = re.compile(r"\s*\d+\s*")


class Configuration(APIModule):
    """Manages connections to local and remote hosts."""

    @expose
    def config_get(self, variable: str, default: Optional[str] = None) -> Optional[str]:
        """Returns the given `variable` from the connection's environment, returning
        `default` if not found."""
        return os.environ[variable] if variable in os.environ else default

    @expose
    def config_set(self, variable: str, value: str) -> str:
        """Sets the given `variable` in the connection's environment, returning
        `default` if not found."""
        if isinstance(value, str):
            env_value = value
        elif isinstance(value, bool):
            env_value = "1" if value else "0"
        else:
            env_value = str(value, "utf")
        os.environ[variable] = env_value
        return value

    @expose
    def config_has(self, variable: str) -> bool:
        """Sets the given `variable` in the connection's environment, returning
        `default` if not found."""
        return variable in os.environ

    @expose
    def config_clear(self, variable: str) -> Optional[str]:
        """Clears the given `variable` from connection's environment.
        `default` if not found."""
        if variable in os.environ:
            value = os.environ[variable]
            del os.environ[variable]
            return value
        else:
            return None

    @expose
    def config_get_variant(self, group: str) -> Optional[str]:
        detector_name = f"detect_{group}"
        if hasattr(self.api, detector_name):
            return getattr(self.api, detector_name)()
        else:
            return self.config_get(f"default.{group}")

    @expose
    def config_command(self, command: str) -> str:
        """Returns the normalized/configured command replacing the given
        command."""
        return command

# EOF
