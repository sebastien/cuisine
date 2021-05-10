import re
from ..api import APIModule
from ..decorators import requires, expose

RE_COMMAND = re.compile(r"\s*([A-Za-z0-9\-]+)(.*)")


class CommandAPI(APIModule):

    @expose
    def command(self, name: str) -> str:
        """Returns the normalized command name. This first tries to find a match
        in `DEFAULT_COMMANDS` and extract it, and then look for a `COMMAND_{name}`
        in the environment."""
        if match := RE_COMMAND.match(name):
            cmd = match.group(1)
            params = match.group(2) or ""
            if cmd in DEFAULT_COMMANDS:
                cmd = self.command(DEFAULT_COMMANDS[cmd])
            cmd_env = cmd.replace("-", "_").upper()
            return self.api.env_get(f"COMMAND_{cmd_env}", cmd) + params
        else:
            return name

    @expose
    @requires("which")
    def command_check(self, command: str) -> bool:
        """Tests if the given command is available on the system."""
        return self.api.run("which '{command}' >& /dev/null && echo OK ; true").endswith("OK")

    @expose
    def command_ensure(self, command: str, package=None) -> bool:
        """Ensures that the given command is present, if not installs the
        package with the given name, which is the same as the command by
        default."""
        if package is None:
            package = command
        if not self.command_check(command):
            self.api.package_install(package)
        assert self.command_check(command), \
            "Command was not installed, check for errors: %s" % (command)
        return True


# EOF
