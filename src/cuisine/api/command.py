def command( name:str ) -> str:
    """Returns the normalized command name. This first tries to find a match 
    in `DEFAULT_COMMANDS` and extract it, and then look for a `COMMAND_{name}`
    in the environment."""
    if match := RE_COMMAND.match(name):
        cmd = match.group(1)
        params = match.group(2) or ""
        if cmd in DEFAULT_COMMANDS:
            cmd = command(DEFAULT_COMMANDS[cmd])
        cmd_env = cmd.replace("-", "_").upper()
        return env_get(f"COMMAND_{cmd_env}", cmd) + params
    else:
        return name

def command_check(command):
    """Tests if the given command is available on the system."""
    return run(f"which '{command}' >& /dev/null && echo OK ; true").endswith("OK")


def command_ensure(command, package=None):
    """Ensures that the given command is present, if not installs the
    package with the given name, which is the same as the command by
    default."""
    if package is None:
        package = command
    if not command_check(command):
        package_install(package)
    assert command_check(command), \
        "Command was not installed, check for errors: %s" % (command)



