#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Project   : Cuisine - Server scripting API
# -----------------------------------------------------------------------------
# License   : Revised BSD License
# -----------------------------------------------------------------------------
# Authors   : Sébastien Pierre                     <sebastien.pierre@gmail.com>
#             Thierry Stiegler   (gentoo port)     <thierry.stiegler@gmail.com>
#             Jim McCoy (distro checks and rpm port)      <jim.mccoy@gmail.com>
#             Warren Moore (zypper package)               <warren@wamonite.com>
#             Lorenzo Bivens (pkgin package)          <lorenzobivens@gmail.com>
# -----------------------------------------------------------------------------
# Creation  : 26-Apr-2010
# Last mod  : 30-Apr-2021
# -----------------------------------------------------------------------------

"""
`cuisine` makes it easy to write automatic server installation
and configuration recipes by wrapping common administrative tasks
(installing packages, creating users and groups) in Python
functions.

`cuisine` is designed to work with Fabric and provide all you
need for getting your new server up and running in minutes.

Note, that right now, Cuisine only supports Debian-based Linux
systems.

:copyright: (c) 2011-2021 by Sébastien Pierre.
:license:   BSD, see LICENSE for more details.
"""

import base64
import hashlib
import os
import re
import string
import tempfile
import subprocess
import types
import getpass
import threading
import sys
import tempfile
import functools
from pathlib import Path
from typing import Dict, Tuple, List, Iterable, Optional, Any, Callable, NamedTuple

try:
    # NOTE: Reporter is a custom module that follows the logging interface
    # but provides more backends and options.
    import reporter
    reporter.StdoutReporter.Install()
    reporter.setLevel(reporter.TRACE)
    LOGGING_BYTES = False
    logging = reporter.bind("cuisine")
except ImportError:
    LOGGING_BYTES = True
    import logging

VERSION = "2.0.0"
NOTHING = base64
RE_SPACES = re.compile("[\s\t]+")
RE_COMMAND = re.compile(r"\s*([A-Za-z0-9\-]+)(.*)")
STRINGIFY_MAXSTRING = 80
STRINGIFY_MAXLISTSTRING = 20
MAC_EOL = "\n"
UNIX_EOL = "\n"
WINDOWS_EOL = "\r\n"
MODE_LOCAL = "CUISINE_MODE_LOCAL"
MODE_SUDO = "CUISINE_MODE_SUDO"
MODE_DEBUG = "CUISINE_MODE_DEBUG"
SUDO_PASSWORD = "CUISINE_SUDO_PASSWORD"
OPTION_PACKAGE = "CUISINE_OPTION_PACKAGE"
OPTION_PYTHON_PACKAGE = "CUISINE_OPTION_PYTHON_PACKAGE"
OPTION_OS_FLAVOUR = "CUISINE_OPTION_OS_FLAVOUR"
OPTION_USER = "CUISINE_OPTION_USER"
OPTION_GROUP = "CUISINE_OPTION_GROUP"
OPTION_HASH = "CUISINE_OPTION_HASH"
OPTION_TRANSPORT = "CUISINE_OPTION_TRANSPORT"
OPTIONS = (OPTION_PACKAGE, OPTION_PYTHON_PACKAGE, OPTION_OS_FLAVOUR,
           OPTION_USER, OPTION_GROUP, OPTION_HASH, OPTION_TRANSPORT)
CMD_APT_GET = 'DEBIAN_FRONTEND=noninteractive apt-get -q --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" '
CMD_APT_CACHE = 'DEBIAN_FRONTEND=noninteractive apt-cache '
STATS = None
STATUS_SUCCESS = (0,)
RE_INT = re.compile(r"\s*\d+\s*")

AVAILABLE_OPTIONS = dict(
    package=["apt", "yum", "zypper", "pacman", "emerge", "pkgin", "pkgng"],
    python_package=["easy_install", "pip"],
    os_flavour=["linux",  "bsd"],
    user=["linux",  "bsd"],
    group=["linux",  "bsd"],
    hash=["python", "openssl"],
    transport=["paramiko", "mitogen", "parallel-ssh"],
)

DEFAULT_OPTIONS = dict(
    package="apt",
    python_package="pip",
    os_flavour="linux",
    user="linux",
    group="linux",
    hash="python",
    transport="paramiko",
)


DEFAULT_COMMANDS = {
    "python":"python3",
    "pip":"python -m pip",
}

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

    # I'm not sure how that even works, as we're not initializing self with
    # `out`, but it still does work.
    def __init__(self, res:Tuple[str,int,bytes, bytes]):
        str.__init__(self)
        command, status, out, err = res
        self.command = command
        self.status = status
        self._out = out
        self._err = err
        self._outStr:Optional[str] = None
        self._errStr:Optional[str] = None
        self.encoding = "utf8"
        self._value = NOTHING
        # Q: Should we log there?
        if self.out:
            logging.info(self.out)
        if self.err:
            logging.error(self.err)

    @property
    def out( self  ) -> str:
        if self._outStr is None:
            self._outStr = str(self._out, self.encoding)
        return self._outStr

    @property
    def err( self  ) -> str:
        if self._errStr is None:
            self._errStr = str(self._err, self.encoding)
        return self._errStr

    @property
    def out_bytes( self  ) -> bytes:
        return self._out

    @property
    def err_bytes( self  ) -> bytes:
        return self._err

    @property
    def value(self) -> Any:
        if self._value is NOTHING:
            self._value = self.last_line
        return self._value

    @property
    def has_value(self) -> bool:
        return bool(self.value)

    @property
    def last_line(self) -> str:
        """Returns the last line, stripping the trailing EOL"""
        i = self.out.rfind("\n", 0, -2)
        return (self.out if i == -1 else self.out[i:]).rstrip("\n")

    @property
    def is_success(self) -> bool:
        """Returns true if the command status is one of `STATUS_SUCCESS`"""
        return self.status in STATUS_SUCCESS

    @property
    def has_failed(self) -> bool:
        return not self.is_success

    def __repr__(self) -> str:
        return f"Command: {self.command}\nstatus: {self.status}\nout: {repr(log_stringify(self.out))}\nerr: {repr(log_stringify(self.err))}"


# =============================================================================
#
# ENVIRONMENT FUNCTIONS
#
# =============================================================================


def env_get(variable: str, default: Optional[str] = None) -> str:
    """Returns the given `variable` from the *local* environment, returning
    `default` if not found."""
    value = os.environ[variable] if variable in os.environ else default
    if isinstance(value, str):
        if match := RE_INT.match(value):
            return int(value)
        else:
            return value
    else:
        return value


def env_set(variable: str, value: str) -> str:
    """Sets the given `variable` in the *local* environment, returning
    `default` if not found."""
    if isinstance(value, str):
        env_value = value
    elif isinstance(value, bool):
        env_value = "1" if value else "0"
    else:
        env_value = str(value, "utf")
    os.environ[variable] = env_value
    return value


def env_clear(variable: str) -> str:
    """Clears the given `variable` from the *local* environment.
    `default` if not found."""
    if variable in os.environ:
        value = os.environ[variable]
        del os.environ[variable]
        return value
    else:
        return None


# =============================================================================
#
# LOGGING
#
# =============================================================================


def log_debug(message: str):
    logging.debug(log_string(message))


def log_error(message: str):
    logging.error(log_string(message))


def log_string(message: str):
    """Ensures that the string is safe for logging"""
    return bytes(message, "UTF8") if LOGGING_BYTES else message


def log_stringify(value):
    """Turns the given value in a user-friendly string that can be displayed"""
    if type(value) in (str, bytes) and len(value) > STRINGIFY_MAXSTRING:
        return f"{value[0:STRINGIFY_MAXSTRING]}…"
    elif type(value) in (list, tuple) and len(value) > 10:
        return f"[{', '.join([log_stringify(_) for _ in value[0:STRINGIFY_MAXLISTSTRING]])},…]"
    else:
        return str(value)


def log_call(function, args, kwargs):
    """Logs the given function call"""
    function_name = function.__name__
    a = ", ".join([log_stringify(_) for _ in args] + [str(k) +
                                                      "=" + log_stringify(v) for k, v in kwargs.items()])
    log_debug("{0}({1})".format(function_name, a))

# =============================================================================
#
# DECORATORS
#
# =============================================================================


def requires(commands=()):
    """Decorator that captures requirement metdata for operations."""
    def decorator(f):
        return f
    return decorator


def logged(message=None):
    """Logs the invoked function name and arguments."""
    # TODO: Options - prevent sub @logged to output anything
    # TODO: Message - allow to specify a message
    # TODO: Category - read/write/exec as well as mode
    # [2013-10-28T10:18:32] user@host [sudo|user] [R/W] cuinine.function(xx,xxx,xx) [time]
    # [2013-10-28T10:18:32] user@host [sudo|user] [!] Exception
    def logged_wrapper(function, message=message):
        def wrapper(*args, **kwargs):
            log_call(function, args, kwargs)
            return function(*args, **kwargs)
        # We copy name and docstring
        functools.update_wrapper(wrapper, function)
        return wrapper
    if type(message) == types.FunctionType:
        return logged_wrapper(message, None)
    else:
        return logged_wrapper


def dispatch(prefix=None, multiple=False):
    """Dispatches the current function to specific implementation. The `prefix`
    parameter indicates the common option prefix, and the `select_[option]()`
    function will determine the function suffix.

    For instance the package functions are defined like this:

    ```
    @dispatch("package")
    def package_ensure(...):
            ...
    def package_ensure_apt(...):
            ...
    def package_ensure_yum(...):
            ...
    ```

    and then when a user does

    ```
    cuisine.select_package("yum")
    cuisine.package_ensure(...)
    ```

    then the `dispatch` function will dispatch `package_ensure` to
    `package_ensure_yum`.

    If your prefix is the first word of the function name before the
    first `_` then you can simply use `@dispatch` without parameters.
    """
    def dispatch_wrapper(function, prefix=prefix):
        def wrapper(*args, **kwargs):
            function_name = function.__name__
            _prefix = prefix or function_name.split("_")[0].replace(".", "_")
            select = env_get(f"CUISINE_OPTION_{_prefix.upper()}")
            assert select, f"No option defined for: {_prefix.upper()}, call select_{prefix.lower().replace('.','_')} (<YOUR OPTION>) to set it"
            function_name = function.__name__ + "_" + select
            specific = eval(function_name)
            if specific:
                if type(specific) == types.FunctionType:
                    if multiple and args and isinstance(args[0], list):
                        rest = args[1:]
                        return [specific(_, *rest, **kwargs) for _ in args[0]]
                    else:
                        return specific(*args, **kwargs)
                else:
                    raise Exception(f"Function expected for: {function_name}")
            else:
                raise Exception(
                    f"Function variant not defined: {function_name}")
        # We copy name and docstring
        functools.update_wrapper(wrapper, function)
        return wrapper
    if type(prefix) == types.FunctionType:
        return dispatch_wrapper(prefix, None)
    else:
        return dispatch_wrapper

# =============================================================================
#
# MODES
#
# =============================================================================


def sudo_password(password=None):
    """Sets the password for the sudo command."""
    if password is None:
        return env_get(SUDO_PASSWORD)
    else:
        if not password:
            env_clear(SUDO_PASSWORD)
        else:
            env_set(SUDO_PASSWORD, password)


class __mode_switcher:
    """A class that can be used to switch Cuisine's run modes by
    instanciating the class or using it as a context manager"""
    MODE_VALUE = True
    MODE_KEY = None

    def __init__(self, value=None):
        self.oldMode = env_get(self.MODE_KEY)
        env_set(self.MODE_KEY, self.MODE_VALUE if value is None else value)

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        if self.oldMode is None:
            env_clear(self.MODE_KEY)
        else:
            env_set(self.MODE_KEY, self.oldMode)


class mode_local(__mode_switcher):
    """Sets Cuisine into local mode, where run/sudo won't go through
    Fabric's API, but directly through a popen. This allows you to
    easily test your Cuisine scripts without using Fabric."""
    MODE_KEY = MODE_LOCAL
    MODE_VALUE = True


class mode_remote(__mode_switcher):
    """Comes back to Fabric's API for run/sudo. This basically reverts
    the effect of calling `mode_local()`."""
    MODE_KEY = MODE_LOCAL
    MODE_VALUE = False


class mode_user(__mode_switcher):
    """Cuisine functions will be executed as the current user."""
    MODE_KEY = MODE_SUDO
    MODE_VALUE = False


class mode_sudo(__mode_switcher):
    """Cuisine functions will be executed with sudo."""
    MODE_KEY = MODE_SUDO
    MODE_VALUE = True


class mode_debug(__mode_switcher):
    """Sets Cuisine into debug mode, where commands are not
    exectued but instead logged."""
    MODE_KEY = MODE_DEBUG
    MODE_VALUE = True


def mode(key):
    """Queries the given Cuisine mode (ie. MODE_LOCAL, MODE_SUDO)"""
    return env_get(key, False)


def is_local(): return mode(MODE_LOCAL)
def is_remote(): return not mode(MODE_LOCAL)
def is_sudo(): return mode(MODE_SUDO)
def is_debug(): return mode(MODE_DEBUG)


def shell_safe(path):
    """Makes sure that the given path/string is escaped and safe for shell"""
    return "".join([("\\" + _) if _ in " '\";`|" else _ for _ in path])


def quote_safe(line):
    """Makes sure that the single quotes are escaped"""
    return line.replace("'", "\\'")

# =============================================================================
#
# OPTIONS
#
# =============================================================================


def option( name:str ) -> str:
    """Returns the current value of the option with the given name."""
    assert name in AVAILABLE_OPTIONS, f"Unrecognized option {name}, expected one of: {', '.join(AVAILABLE_OPTIONS.keys())}"
    return env_get(name) or DEFAULT_OPTIONS.get(name)

def options() -> Dict[str, str]:
    """Retrieves the list of options as a dictionary. Options can be set with
    the `options_*`  functions."""

    return {k: env_get(k) for k in (
            OPTION_PACKAGE,
            OPTION_PYTHON_PACKAGE,
            OPTION_OS_FLAVOUR,
            OPTION_USER,
            OPTION_GROUP,
            OPTION_HASH)}


def __select_helper(name:str, envvar:str) -> Callable[[Optional[str]],Tuple[str,Iterable[str]]]:
    def select(selection=None):
        supported = AVAILABLE_OPTIONS[name]
        if not (selection is None):
            assert selection in supported, f"Option must be one of: {supported}"
            env_set(envvar, selection)
        return (env_get(envvar), supported)
    return select

select_package = __select_helper("package", OPTION_PACKAGE)
select_python_package = __select_helper("python_package", OPTION_PYTHON_PACKAGE)
select_user = __select_helper("user", OPTION_USER)
select_group = __select_helper("group", OPTION_GROUP)
select_os_flavour = __select_helper("os_flavour", OPTION_OS_FLAVOUR)
select_hash = __select_helper("hash", OPTION_HASH)
select_transport = __select_helper("transport", OPTION_TRANSPORT)

def is_ok(text: str) -> bool:
    """Tells if the given text ends with "OK", swallowing trailing blanks."""
    while text and text[-1] in "\r\n\t ":
        text = text[:-1]
    return text.endswith("OK")

# =============================================================================
#
# RUN/SUDO METHODS
#
# =============================================================================


def run_remote(command, sudo=False, shell=True, pty=True, combine_stderr=None, connection=None) -> CommandOutput:
    """Runs the given command on the last remote connection, or the given
    `connection` if provided. This requires calling `connect()` beforehand."""
    if not (connection or connections):
        raise ValueError(f"No connection given, call 'connect()' first: {connections}")
    c = connection or connections[-1]
    # TODO: Take care of the sudo, shell, combine_stderr options
    return c.run(command)

def run_local(command, sudo=False, shell=True, combine_stderr=None) -> CommandOutput:
    """Liek `run_local_raw`, but returns a `CommandOutput`"""
    raw_res = run_local_raw(command, sudo=sudo, shell=shell, combine_stderr=combine_stderr)
    res = CommandOutput(raw_res)
    return res

# TODO: Remove the command output, it's going to be more easily serializable
def run_local_raw(command:str, sudo=False, shell=True, combine_stderr=None, encoding="utf8") -> Tuple[str,int,bytes,bytes]:
    """Low-level command running function."""
    # TODO: Pass the SUDO_PASSWORD variable to the command here
    if sudo:
        command = "sudo " + command
    stderr = subprocess.STDOUT if combine_stderr else subprocess.PIPE
    # TODO: We might want to rework how we manage the CWD. In Fabric, that was lpwd
    run_in = "."
    log_debug("run_local: {0} in {1}".format(command, run_in))
    process = subprocess.Popen(
        command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=run_in)
    # NOTE: This is not ideal, but works well.
    # See http://stackoverflow.com/questions/15654163/how-to-capture-streaming-output-in-python-from-subprocess-communicate
    # At some point, we should use a single thread.
    out:List[bytes] = []
    err:List[bytes] = []
    # FIXME: This does not seem to stream

    def stdout_reader():
        for line in process.stdout:
            line = line or b""
            if line:
                log_debug(str(line, encoding).rstrip("\n").rstrip("\r"))
            out.append(line)

    def stderr_reader():
        for line in process.stderr:
            line = line or b""
            log_error(str(line, encoding).rstrip("\n").rstrip("\r"))
            err.append(line)
    t0 = threading.Thread(target=stdout_reader)
    t1 = threading.Thread(target=stderr_reader)
    t0.start()
    t1.start()
    process.wait()
    t0.join()
    t1.join()
    return (command, process.returncode, b"".join(out), b"".join(err))

def run_debug(command, sudo=False, shell=True, pty=True, combine_stderr=None):
    sys.stdout.write("debug: {0}{1}".format("sudo " if sudo else "", command))


def run_sudo(*args, **kwargs):
    """Runs the command as a super user"""
    kwargs["sudo"] = True
    return (run_local if is_local() else run_remote)(*args, **kwargs)


def run_user(*args, **kwargs):
    """Runs the command as a regular user"""
    kwargs["sudo"] = False
    return (run_local if is_local() else run_remote)(*args, **kwargs)


def run(*args, **kwargs):
    """Runs the given command, taking into account
    the `MODE_LOCAL`, `MODE_SUDO` and `MODE_DEBUG` modes of Cuisine."""
    if is_sudo():
        kwargs.setdefault("sudo", True)
    if is_debug():
        return run_debug(*args, **kwargs)
    elif is_local():
        return run_local(*args, **kwargs)
    else:
        return run_remote(*args, **kwargs)


class __cd_context:
    """A helper object returned by `cd`."""

    def __init__(self, path:str):
        self.path = path

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        cd(self.path, context=False)


def cd(path:str, context=True) -> Optional[__cd_context]:
    """Changes the current directory. Can be used in a `with`
    statement, and will change back to the current directory."""
    # FIXME: This will not work with multiple connections
    if not isinstance(path,str): raise ValueError(f"Expected string, got: '{path}'")
    current = pwd()
    if is_local():
        norm_path = path_local_normalize(path)
        if not norm_path.exists():
            raise ValueError(f"Local path does not exists: {path}")
        os.chdir(norm_path)
    else:
        connection().cd(path)
    return __cd_context(current) if context else None


def pwd() -> str:
    """Returns the current directory."""
    return run("pwd").value

@logged
def sudo(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the
    'cuisine.MODE_SUDO' global to tell whether the command should be run as
    regular user or sudo."""
    with mode_sudo():
        return run(*args, **kwargs)



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

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[Path]=None ):
        self.key =  Path(os.path.normpath(os.path.expanduser(os.path.expandvars(key)))) if key else None
        self.password:Optional[str] = password
        self.user:Optional[str] = user
        self.host:Optional[str] = "localhost"
        self.port = 22
        self.isConnected = False
        self.type = self.TYPE
        self._path:Optional[str] = None
        self.cd_prefix:str = ""
        self.init()

    @property
    def path( self ) -> Optional[str]:
        return self._path 

    @path.setter
    def path( self, value:str ):
        self._path = value
        # We store the cd_prefix as we need to prefix commands with
        # a directory.
        self.cd_prefix = f"cd '{shell_safe(value)}';"if value else ""

    def init( self ):
        pass

    def connect( self, host:str, port=None ) -> 'Connection':
        assert not self.isConnected, "Connection already made, call 'disconnect' first"
        self.host = host or self.host
        self.port = port or self.port
        return self

    def reconnect( self, user:Optional[str], host:Optional[str], port:Optional[int] ) -> 'Connection':
        self.disconnect()
        self.user = user or self.user
        host = host or self.host
        port = port or self.port
        return self.connect(host, port)

    def run( self, command:str ) -> Optional[CommandOutput]:
        logging.info(command)
        return None

    def cd( self, path:str ) -> bool:
        raise NotImplementedError

    def upload( self, remote:str, local:str ) -> bool:
        """Copies from the local file to the remote path"""
        local_path = Path(os.path.normpath(os.path.expanduser(os.path.expandvars(local))))
        if not local_path.exists():
            raise ValueError(f"Local path does not exists: '{local}'")
        return True

    def write( self, remote:str, content:bytes ) -> bool:
        """Writes the given content to the remote path"""
        return True

    def disconnect( self ) -> bool:
        return self.isConnected

# SEE: https://gist.github.com/mlafeldt/841944
class ParamikoConnection(Connection):
    """Manages a remote connection through Paramiko.
     See <https://docs.paramiko.org>"""

    TYPE = "paramiko"

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[Path]=None ):
        super().__init__(user,password,key)

    def init( self ):
        # SEE: https://docs.paramiko.org/en/stable/api/client.html
        try:
            import paramiko
            import paramiko.ssh_exception as paramiko_exceptions
        except ImportError as e:
            logging.error("Paramiko <https://docs.paramiko.org> is required: python -m pip install --user paramiko")
            raise e
        self.paramiko = paramiko
        self._sftp = None
        self.paramiko_exceptions = paramiko_exceptions

    @property
    def sftp( self ):
        if not self._sftp:
            self._sftp = self.context.open_sftp()
        return self._sftp

    def connect( self, host:str, port=22 ) -> 'ParamikoConnection':
        # NOTE: Connect will update self.{host,port}
        super().connect(host, port)
        # SEE: https://docs.paramiko.org/en/stable/api/client.html
        self.context = client = self.paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(self.paramiko.WarningPolicy)
        try:
            client.connect(self.host, username=self.user, port=self.port, key_filename=self.key, look_for_keys=True)
        except  self.paramiko_exceptions.AuthenticationException as e:
            logging.fatal(f"Cannot connect to {self.user}@{self.host}:{self.port} using {self.type}: {e}")
            self.context = None
            self.isConnected = False
            return self
        return self

    def run( self, command ) -> CommandOutput:
        if not self.context:
            logging.error(f"Connection failed, cannot run: {command}")
            return CommandOutput((command,127,b"",b""))
        else:
            super().run(command)
            cmd = self.cd_prefix + command
            _, stdout, stderr = self.context.exec_command(cmd)
            # FIXME: We might be deadlocking here, we might want to reuse the 
            # threaded readers.
            err = stderr.read()
            out = stdout.read()
            status = stdout.channel.recv_exit_status()
            return CommandOutput((command, status, out, err))

    def upload( self, remote:str, local:str ) -> bool:
        if not super().upload(remote, local):
            raise ValueError("Could not upload", remote, local)
            return False
        self.sftp.put(local, remote)
        return True

    def write( self, remote:str, content:bytes ) -> bool:
        if not super().write(remote, content):
            return False
        else:
            with self.sftp.open(remote, "wb") as f:
                f.write(content)
            return True

    def cd( self, path:str ) -> bool:
        self.sftp.chdir(path)
        self.path = path
        return True

    def disconnect( self ) -> bool:
        if super().disconnect():
            if self._sftp:
                self._sftp.close()
                self._sftp = None
            self.context.close()
            self.context = None
            return True
        else:
            return False

class MitogenConnection(Connection):
    """Manages a remote connection through Mitogen. 
     See <https://mitogen.networkgenomics.com/>."""

    TYPE = "mitogen"

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[Path]=None ):
        super().__init__(user,password,key)

    def init( self ):
        try:
            import mitogen
            import mitogen.utils as mitogen_utils
            import mitogen.master as mitogen_master
            import mitogen.ssh as mitogen_ssh
        except ImportError as e:
            logging.error("Mitogen <https://mitogen.networkgenomics.com/> is required: python -m pip install --user mitogen")
            raise e
        self.mitogen = mitogen
        self.mitogen_utils = mitogen_utils
        self.mitogen_master = mitogen_master
        self.mitogen_ssh = mitogen_ssh

    def connect( self, host:str, port=22 ) -> 'MitogenConnection':
        # NOTE: Connect will update self.{host,port}
        super().connect(host, port)
        broker = self.mitogen_master.Broker()
        router = self.mitogen_master.Router(broker)
        try:
            # NOTE: See <https://github.com/mitogen-hq/mitogen/blob/master/mitogen/ssh.py>
            self.context = router.ssh(hostname=self.host, username=self.user, port=self.port, identity_file=self.key)
        except self.mitogen_ssh.PasswordError as e:
            logging.fatal(f"Cannot connect to {self.user}@{self.host}:{self.port} using {self.type}: {e}")
            self.context = None
            self.isConnected = False
            return self
        return self

    def run( self, command ) -> CommandOutput:
        if not self.context:
            logging.error(f"Connection failed, cannot run: {command}")
            return CommandOutput((command,127,b"",b""))
        else:
            super().run(command)
            return CommandOutput(self.context.call(run_local_raw, command))

class ParallelSSHConnection(Connection):

    TYPE = "parallel-ssh"

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[str]=None ):
        super().__init__(user,password,key)

    def init( self ):
        try:
            from pssh.clients import SSHClient
            from pssh.exceptions import AuthenticationError
        except ImportError as e:
            logging.error("parallel-ssh is required: run 'ppython -m pip install --user parallel-ssh' or pick another transport: {transport_options}")
            raise e
        self.SSHClient = SSHClient
        self.AuthenticationError = AuthenticationError
        self.context:Optional[SSHClient] = None

    def connect( self, host:str, port=22 ) -> 'ParallelSSHConnection':
        super().connect(host, port)
        try:
            client = self.SSHClient(host)
        except self.AuthenticationError as e:
            logging.error(f"Cannot connect to f{host}: {e}")
            raise e
        self.context = client
        return self

    def run( self, command ) -> CommandOutput:
        super().run(command)
        out = client.run_command(command)
        return CommandOutput(out=out.stdout, err=out.stdeer, status=out.exist_code)


connections:List[Connection] = []

def connection() -> Optional[Connection]:
    return connections[-1] if connections else None

@logged
def connect(host:str, user:str=NOTHING, password=NOTHING, key=None, transport=None) -> Connection:
    """Connects to the remote host. This is a synchronous process"""
    transport = transport or option("transport")
    transport_options = AVAILABLE_OPTIONS['transport']
    user = getpass.getuser() if user is NOTHING else user
    logging.info(f"Connecting to {user}@{host} using {transport}")
    key_path = Path(os.path.normpath(os.path.expanduser(os.path.expandvars(key)))) if key else None
    if key_path and not key_path.exists():
        raise ValueError(f"Could not find path at: {key_path}")
    if transport == "paramiko":
        result = ParamikoConnection(user=user, password=password, key=key_path).connect(host)
    elif transport == "mitogen":
        result = MitogenConnection(user=user, password=password, key=key_path).connect(host)
    elif transport == "parallel-ssh":
        result = ParallelSSHConnection(user=user, password=password, key=key_path).connect(host)
    else:
        raise ValueError(f"Unknown transport option '{transport}', use one of: {transport_options}")
    connections.append(result)
    return result

def disconnect() -> Connection:
    """Disconnects the current connction, if any."""
    assert connections, "No current active connection"
    return connections.pop().disconnect()


def host(name=NOTHING):
    """Returns or sets the host"""
    if self.connections:
        c = self.connections[-1]
        if name is NOTHING:
            return c.host
        else:
            return c.reconnect(host=host)


def user(name=NOTHING):
    """Returns or sets the host"""
    if self.connections:
        c = self.connections[-1]
        if name is NOTHING:
            return c.user
        else:
            return c.reconnect(user=name)

# =============================================================================
#
# TEXT PROCESSING
#
# =============================================================================


def text_detect_eol(text):
    # FIXME: Should look at the first line
    if text.find("\r\n") != -1:
        return WINDOWS_EOL
    elif text.find("\n") != -1:
        return UNIX_EOL
    elif text.find("\r") != -1:
        return MAC_EOL
    else:
        return "\n"


def text_get_line(text, predicate):
    """Returns the first line that matches the given predicate."""
    for line in text.split("\n"):
        if predicate(line):
            return line
    return ""


def text_normalize(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub(" ", text).strip()


def text_nospace(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub("", text).strip()


def text_replace_line(text, old, new, find=lambda old, new: old == new, process=lambda _: _):
    """Replaces lines equal to 'old' with 'new', returning the new
    text and the count of replacements.

    Returns: (text, number of lines replaced)

    `process` is a function that will pre-process each line (you can think of
    it as a normalization function, by default it will return the string as-is),
    and `find` is the function that will compare the current line to the
    `old` line.

    The finds the line using `find(process(current_line), process(old_line))`,
    and if this matches, will insert the new line instead.
    """
    res = []
    replaced = 0
    eol = text_detect_eol(text)
    for line in text.split(eol):
        if find(process(line), process(old)):
            res.append(new)
            replaced += 1
        else:
            res.append(line)
    return eol.join(res), replaced


def text_replace_regex(text, regex, new, **kwargs):
    """Replace lines that match with the regex returning the new text

    Returns: text

    `kwargs` is for the compatibility with re.sub(),
    then we can use flags=re.IGNORECASE there for example.
    """
    res = []
    eol = text_detect_eol(text)
    for line in text.split(eol):
        res.append(re.sub(regex, new, line, **kwargs))
    return eol.join(res)


def text_ensure_line(text, *lines):
    """Ensures that the given lines are present in the given text,
    otherwise appends the lines that are not already in the text at
    the end of it."""
    eol = text_detect_eol(text)
    res = list(text.split(eol))
    if res[0] == '' and len(res) == 1:
        res = list()
    for line in lines:
        assert line.find(eol) == - \
            1, "No EOL allowed in lines parameter: " + repr(line)
        found = False
        for l in res:
            if l == line:
                found = True
                break
        if not found:
            res.append(line)
    return eol.join(res)


def text_strip_margin(text, margin="|"):
    """Will strip all the characters before the left margin identified
    by the `margin` character in your text. For instance

    ```
                    |Hello, world!
    ```

    will result in

    ```
    Hello, world!
    ```
    """
    res = []
    eol = text_detect_eol(text)
    for line in text.split(eol):
        l = line.split(margin, 1)
        if len(l) == 2:
            _, line = l
            res.append(line)
    return eol.join(res)


def text_template(text, variables):
    """Substitutes '${PLACEHOLDER}'s within the text with the
    corresponding values from variables."""
    template = string.Template(text)
    return template.safe_substitute(variables)

# =============================================================================
#
# FILE OPERATIONS
#
# =============================================================================

def path_local_normalize( path:str ) -> Path:
    """Normalizes the given path, expanding variables and user home."""
    return Path(os.path.normpath(os.path.expanduser(os.path.expandvars(path))))

def file_name(path:str) -> str:
    """Returns the file name for the given path."""
    return os.path.basename(path)

@logged
def file_local_read(path):
    """Reads a *local* file from the given path, expanding '~' and
    shell variables."""
    p = os.path.expandvars(os.path.expanduser(path))
    f = file(p, 'rb')
    t = f.read()
    f.close()
    return t


@logged
def file_backup(path, suffix=".orig", once=False):
    """Backups the file at the given path in the same directory, appending
    the given suffix. If `once` is True, then the backup will be skipped if
    there is already a backup file."""
    backup_path = path + suffix
    if once and file_exists(backup_path):
        return False
    else:
        return run("cp -a {0} {1}".format(
            shell_safe(path),
            shell_safe(backup_path)
        ))


@logged
def file_read(path, default=None):
    """Reads the *remote* file at the given path, if default is not `None`,
    default will be returned if the file does not exist."""
    # NOTE: We use base64 here to be sure to preserve the encoding (UNIX/DOC/MAC) of EOLs
    if default is None:
        assert file_exists(
            path), "cuisine.file_read: file does not exists {0}".format(path)
    elif not file_exists(path):
        return default
    with fabric.context_managers.settings(
            fabric.api.hide('stdout')
    ):
        frame = file_base64(path)
        return base64.b64decode(frame)


def file_exists(path):
    """Tests if there is a *remote* file at the given path."""
    return is_ok(run('test -e %s && echo OK ; true' % (shell_safe(path))))


def file_is_file(path):
    return is_ok(run("test -f %s && echo OK ; true" % (shell_safe(path))))


def file_is_dir(path):
    return is_ok(run("test -d %s && echo OK ; true" % (shell_safe(path))))


def file_is_link(path):
    return is_ok(run("test -L %s && echo OK ; true" % (shell_safe(path))))


@logged
def file_attribs(path, mode=None, owner=None, group=None):
    """Updates the mode/owner/group for the remote file at the given
    path."""
    return dir_attribs(path, mode, owner, group, False)


@logged
def file_attribs_get(path):
    """Return mode, owner, and group for remote path.
    Return mode, owner, and group if remote path exists, 'None'
    otherwise.
    """
    if file_exists(path):
        fs_check = run('stat %s %s' %
                       (shell_safe(path), '--format="%a %U %G"'))
        (mode, owner, group) = fs_check.split(' ')
        return {'mode': mode, 'owner': owner, 'group': group}
    else:
        return None


@logged
def file_write(path:str, content:bytes, mode=None, owner=None, group=None, sudo=None, check=True, scp=False):
    """Writes the given content to the file at the given remote
    path, optionally setting mode/owner/group."""
    # FIXME: Big files are never transferred properly!
    # Gets the content signature and write it to a secure tempfile
    use_sudo = sudo if sudo is not None else is_sudo()
    sig = hashlib.md5(content).hexdigest()
    fd, local_path = tempfile.mkstemp()
    os.write(fd, content)
    # Upload the content if necessary
    if sig != file_md5(path):
        if is_local():
            with mode_sudo(use_sudo):
                run("cp '%s' '%s'" % (shell_safe(local_path), shell_safe(path)))
        else:
            if scp:
                raise NotImplementedError
                # hostname = env_.host_string if len(env_.host_string.split(
                #     ':')) == 1 else env_.host_string.split(':')[0]
                # scp_cmd = 'scp %s %s@%s:%s' % (shell_safe(local_path), shell_safe(
                #     env_.user), shell_safe(hostname), shell_safe(path))
                log_debug('file_write:[localhost]] ' + scp_cmd)
                run_local(scp_cmd)
            else:
                raise NotImplementedError
    # Remove the local temp file
    os.fsync(fd)
    os.close(fd)
    os.unlink(local_path)
    # Ensures that the signature matches
    if check:
        with mode_sudo(use_sudo):
            file_sig = file_md5(path)
        assert sig == file_sig, "File content does not matches file: %s, got %s, expects %s" % (
            path, repr(file_sig), repr(sig))
    with mode_sudo(use_sudo):
        file_attribs(path, mode=mode, owner=owner, group=group)


@logged
def file_ensure(path, mode=None, owner=None, group=None, scp=False):
    """Updates the mode/owner/group for the remote file at the given
    path."""
    if file_exists(path):
        file_attribs(path, mode=mode, owner=owner, group=group)
    else:
        file_write(path, "", mode=mode, owner=owner, group=group, scp=scp)


@logged
def file_upload(local, remote, sudo=None, scp=False):
    """Uploads the local file to the remote path only if the remote path does not
    exists or the content are different."""
    # FIXME: Big files are never transferred properly!
    # XXX: this 'sudo' kw arg shadows the function named 'sudo'
    use_sudo = is_sudo() or sudo
    with open(local, "rb") as f:
        content = f.read()
    sig = hashlib.md5(content).hexdigest()
    if not file_exists(remote) or sig != file_md5(remote):
        if is_local():
            if use_sudo:
                globals()['sudo']("cp '%s' '%s'" %
                                  (shell_safe(local), shell_safe(remote)))
            else:
                run("cp '%s' '%s'" % (local, remote))
        else:
            if scp:
                # TODO: We should be able to run a local command there
                raise NotImplementedError
                # scp_cmd = @scp %s %s@%s:%s' % (shell_safe(local), shell_safe(
                #     env_.user), shell_safe(hostname), shell_safe(remote))
                # log_debug('file_upload():[localhost] ' + scp_cmd)
                # run_local(scp_cmd)
            else:
                connection().upload(remote, local)

@logged
def file_update(path, updater=lambda x: x):
    """Updates the content of the given by passing the existing
    content of the remote file at the given path to the 'updater'
    function. Return true if file content was changed.

    For instance, if you'd like to convert an existing file to all
    uppercase, simply do:

    >   file_update("/etc/myfile", lambda _:_.upper())

    Or restart service on config change:

    >   if file_update("/etc/myfile.cfg", lambda _: text_ensure_line(_, line)): run("service restart")
    """
    assert file_exists(path), "File does not exists: " + path
    old_content = file_read(path)
    new_content = updater(old_content)
    if (old_content == new_content):
        return False
    # assert type(new_content) in (str, unicode, fabric.operations._AttributeString), "Updater must be like (string)->string, got: %s() = %s" %  (updater, type(new_content))
    file_write(path, new_content)
    return True


@logged
def file_append(path, content, mode=None, owner=None, group=None):
    """Appends the given content to the remote file at the given
    path, optionally updating its mode/owner/group."""
    # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
    run('echo "%s" | openssl base64 -A -d >> %s' %
        (base64.b64encode(content), shell_safe(path)))
    file_attribs(path, mode, owner, group)


@logged
def file_unlink(path):
    if file_exists(path):
        run("unlink %s" % (shell_safe(path)))


@logged
def file_link(source, destination, symbolic=True, mode=None, owner=None, group=None):
    """Creates a (symbolic) link between source and destination on the remote host,
    optionally setting its mode/owner/group."""
    if file_exists(destination) and (not file_is_link(destination)):
        raise Exception(
            "Destination already exists and is not a link: %s" % (destination))
    # FIXME: Should resolve the link first before unlinking
    if file_is_link(destination):
        file_unlink(destination)
    if symbolic:
        run('ln -sf %s %s' % (shell_safe(source), shell_safe(destination)))
    else:
        run('ln -f %s %s' % (shell_safe(source), shell_safe(destination)))
    file_attribs(destination, mode, owner, group)

# SHA256/MD5 sums with openssl are tricky to get working cross-platform
# SEE: https://github.com/sebastien/cuisine/pull/184#issuecomment-102336443
# SEE: http://stackoverflow.com/questions/22982673/is-there-any-function-to-get-the-md5sum-value-of-file-in-linux


@logged
def file_base64(path):
    """Returns the base64-encoded content of the file at the given path."""
    if env_get(OPTION_HASH) == "python":
        return run("cat {0} | python -c 'import sys,base64;sys.stdout.write(base64.b64encode(sys.stdin.read()))'".format(shell_safe((path))))
    else:
        return run("cat {0} | openssl base64".format(shell_safe((path))))


@logged
def file_sha256(path):
    """Returns the SHA-256 sum (as a hex string) for the remote file at the given path."""
    # NOTE: In some cases, sudo can output errors in here -- but the errors will
    # appear before the result, so we simply split and get the last line to
    # be on the safe side.
    if env_get(OPTION_HASH) == "python":
        if not _hashlib_supported():
            raise EnvironmentError(
                "Remote host has not hashlib support. Please, use select_hash('openssl')")
        if file_exists(path):
            return run("cat {0} | python -c 'import sys,hashlib;sys.stdout.write(hashlib.sha256(sys.stdin.read()).hexdigest())'".format(shell_safe((path))))
        else:
            return None
    else:
        if file_exists(path):
            return run('openssl dgst -sha256 %s' % (shell_safe(path))).split("\n")[-1].split(")= ", 1)[-1].strip()
        else:
            return None


@logged
def file_md5(path):
    """Returns the MD5 sum (as a hex string) for the remote file at the given path."""
    # NOTE: In some cases, sudo can output errors in here -- but the errors will
    # appear before the result, so we simply split and get the last line to
    # be on the safe side.
    if env_get(OPTION_HASH) == "python":
        if not _hashlib_supported():
            raise EnvironmentError(
                "Remote host has not hashlib support. Please, use select_hash('openssl')")
        if file_exists(path):
            return run("cat {0} | python -c 'import sys,hashlib;sys.stdout.write(hashlib.md5(sys.stdin.read()).hexdigest())'".format(shell_safe((path))))
        else:
            return None
    else:
        if file_exists(path):
            return run('openssl dgst -md5 %s' % (shell_safe(path))).split("\n")[-1].split(")= ", 1)[-1].strip()
        else:
            return None


def _hashlib_supported():
    """ Returns True if remote host has hashlib support on Python """
    return run("python -c 'import hashlib'", warn_only=True).succeeded


# =============================================================================
#
# PROCESS OPERATIONS
#
# =============================================================================

@logged
def process_find(name, exact=False):
    """Returns the pids of processes with the given name. If exact is `False`
    it will return the list of all processes that start with the given
    `name`."""
    is_string = isinstance(name, str) or isinstance(name, unicode)
    # NOTE: ps -A seems to be the only way to not have the grep appearing
    # as well
    if is_string:
        processes = run("ps -A | grep {0} ; true".format(name))
    else:
        processes = run("ps -A")
    res = []
    for line in processes.split("\n"):
        if not line.strip():
            continue
        line = RE_SPACES.split(line.strip(), 3)
        # 3010 pts/1    00:00:07 gunicorn
        # PID  TTY      TIME     CMD
        # 0    1        2        3
        # We skip lines that are not like we expect them (sometimes error
        # message creep up the output)
        if len(line) < 4:
            continue
        pid, tty, time, command = line
        if is_string:
            if pid and ((exact and command == name) or (not exact and command.find(name) >= 0)):
                res.append(pid)
        elif name(line) and pid:
            res.append(pid)
    return res


@logged
def process_kill(name, signal=9, exact=False):
    """Kills the given processes with the given name. If exact is `False`
    it will return the list of all processes that start with the given
    `name`."""
    for pid in process_find(name, exact):
        run("kill -s {0} {1} ; true".format(signal, pid))

# =============================================================================
#
# DIRECTORY OPERATIONS
#
# =============================================================================


@logged
def dir_attribs(path, mode=None, owner=None, group=None, recursive=False):
    """Updates the mode/owner/group for the given remote directory."""
    recursive = recursive and "-R " or ""
    if mode:
        run('chmod %s %s %s' % (recursive, mode,  shell_safe(path)))
    if owner:
        run('chown %s %s %s' % (recursive, owner, shell_safe(path)))
    if group:
        run('chgrp %s %s %s' % (recursive, group, shell_safe(path)))


def dir_exists(path):
    """Tells if there is a remote directory at the given path."""
    return run('test -d %s && echo OK ; true' % (shell_safe(path))).endswith("OK")


@logged
def dir_remove(path, recursive=True):
    """ Removes a directory """
    flag = ''
    if recursive:
        flag = 'r'
    if dir_exists(path):
        return run('rm -%sf %s && echo OK ; true' % (flag, shell_safe(path)))


def dir_ensure_parent( path:str ):
    """Ensures that the parent directory of the given path exists"""
    dir_ensure(os.path.dirname(path))
    return path

def dir_ensure(path:str, recursive=True, mode=None, owner=None, group=None) -> str:
    """Ensures that there is a remote directory at the given path,
    optionally updating its mode/owner/group.

    If we are not updating the owner/group then this can be done as a single
    ssh call, so use that method, otherwise set owner/group after creation."""
    if not dir_exists(path):
        run('mkdir %s %s' % (recursive and "-p" or "", shell_safe(path)))
    if owner or group or mode:
        dir_attribs(path, owner=owner, group=group,
                    mode=mode, recursive=recursive)
    return path

# =============================================================================
#
# PACKAGE OPERATIONS
#
# =============================================================================


@logged
@dispatch(multiple=True)
def package_available(package: str) -> bool:
    """Tells if the given package is available"""


@logged
@dispatch(multiple=True)
def package_installed(package, update=False) -> bool:
    """Tells if the given package is installed or not."""


@logged
@dispatch(multiple=True)
def package_upgrade(distupgrade=False):
    """Updates every package present on the system."""


@logged
@dispatch(multiple=True)
def package_update(package=None):
    """Updates the package database (when no argument) or update the package
    or list of packages given as argument."""


@logged
@dispatch
def package_install(package, update=False):
    """Installs the given package/list of package, optionally updating
    the package database."""


@logged
@dispatch(multiple=True)
def package_ensure(package, update=False):
    """Tests if the given package is installed, and installs it in
    case it's not already there. If `update` is true, then the
    package will be updated if it already exists."""


@logged
@dispatch
def package_clean(package=None):
    """Clean the repository for un-needed files."""


@logged
@dispatch(multiple=True)
def package_remove(package, autoclean=False):
    """Remove package and optionally clean unused packages"""

# -----------------------------------------------------------------------------
# APT PACKAGE (DEBIAN/UBUNTU)
# -----------------------------------------------------------------------------


@logged
def repository_ensure_apt(repository):
    package_ensure_apt('python-software-properties')
    sudo("add-apt-repository --yes " + repository)


def apt_get(cmd):
    cmd = CMD_APT_GET + cmd
    result = sudo(cmd)
    # If the installation process was interrupted, we might get the following message
    # E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a' to correct the problem.
    if "sudo dpkg --configure -a" in result:
        sudo("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
        result = sudo(cmd)
    return result


def apt_cache(cmd):
    cmd = CMD_APT_CACHE + cmd
    return run(cmd)


def package_available_apt(package: str) -> bool:
    return apt_cache(f" search '^{quote_safe(package)}$'").has_value


def package_update_apt(package=None):
    if package == None:
        return apt_get("-q --yes update")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        return apt_get(' install --only-upgrade ' + package)


def package_upgrade_apt(distupgrade=False):
    if distupgrade:
        return apt_get("dist-upgrade")
    else:
        return apt_get("install --only-upgrade")


def package_install_apt(package, update=False):
    if update:
        apt_get("update")
    if type(package) in (list, tuple):
        package = " ".join(package)
    return apt_get("install " + package)


def package_installed_apt(package, update=False) -> False:
    pkg = package.strip()
    if not pkg:
        raise ValueError(f"Package argument is empty: {repr(package)}")
    # The most reliable way to detect success is to use the command status
    # and suffix it with OK. This won't break with other locales.
    status = run(
        f"dpkg-query -W -f='${{Status}} ' '{pkg}' && echo OK;true")
    return status.last_line.endswith("OK")


def package_ensure_apt(package, update=False):
    """Ensure apt packages are installed"""
    if isinstance(package, str):
        package = package.split()
    res = {}
    for p in package:
        p = p.strip()
        if not p:
            continue
        # The most reliable way to detect success is to use the command status
        # and suffix it with OK. This won't break with other locales.
        status = run("dpkg-query -W -f='${Status} ' %s && echo OK;true" % p)
        if not status.endswith("OK") or "not-installed" in status:
            package_install_apt(p)
            res[p] = False
        else:
            if update:
                package_update_apt(p)
            res[p] = True
    if len(res) == 1:
        return next(_ for _ in res.values())
    else:
        return res


def package_clean_apt(package=None):
    if type(package) in (list, tuple):
        package = " ".join(package)
    return apt_get("-y --purge remove %s" % package)


def package_remove_apt(package, autoclean=False):
    apt_get('remove ' + package)
    if autoclean:
        apt_get("autoclean")

# -----------------------------------------------------------------------------
# YUM PACKAGE (RedHat, CentOS)
# added by Prune - 20120408 - v1.0
# -----------------------------------------------------------------------------


def repository_ensure_yum(repository):
    raise Exception("Not implemented for Yum")


def package_upgrade_yum():
    sudo("yum -y update")


def package_update_yum(package=None):
    if package == None:
        sudo("yum -y update")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("yum -y upgrade " + package)


def package_install_yum(package, update=False):
    if update:
        sudo("yum -y update")
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("yum -y install %s" % (package))


def package_ensure_yum(package, update=False):
    status = run("yum list installed %s ; true" % package)
    if status.find("No matching Packages") != -1 or status.find(package) == -1:
        package_install_yum(package, update)
        return False
    else:
        if update:
            package_update_yum(package)
        return True


def package_clean_yum(package=None):
    sudo("yum -y clean all")


def package_remove_yum(package, autoclean=False):
    sudo("yum -y remove %s" % (package))

# -----------------------------------------------------------------------------
# ZYPPER PACKAGE (openSUSE)
# -----------------------------------------------------------------------------


def repository_ensure_zypper(repository):
    repository_uri = repository
    if repository[-1] != '/':
        repository_uri = repository.rpartition("/")[0]
    status = run("zypper --non-interactive --gpg-auto-import-keys repos -d")
    if status.find(repository_uri) == -1:
        sudo("zypper --non-interactive --gpg-auto-import-keys addrepo " + repository)
        sudo("zypper --non-interactive --gpg-auto-import-keys modifyrepo --refresh " + repository_uri)


def package_upgrade_zypper():
    sudo("zypper --non-interactive --gpg-auto-import-keys update --type package")


def package_update_zypper(package=None):
    if package == None:
        sudo("zypper --non-interactive --gpg-auto-import-keys refresh")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("zypper --non-interactive --gpg-auto-import-keys update --type package " + package)


def package_install_zypper(package, update=False):
    if update:
        package_update_zypper()
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("zypper --non-interactive --gpg-auto-import-keys install --type package --name " + package)


def package_ensure_zypper(package, update=False):
    status = run(
        "zypper --non-interactive --gpg-auto-import-keys search --type package --installed-only --match-exact %s ; true" % package)
    if status.find("No packages found.") != -1 or status.find(package) == -1:
        package_install_zypper(package)
        return False
    else:
        if update:
            package_update_zypper(package)
        return True


def package_clean_zypper():
    sudo("zypper --non-interactive clean")


def package_remove_zypper(package, autoclean=False):
    sudo("zypper --non-interactive remove %s" % (package))

# -----------------------------------------------------------------------------
# PACMAN PACKAGE (Arch)
# -----------------------------------------------------------------------------


def repository_ensure_pacman(repository):
    raise Exception("Not implemented for Pacman")


def package_update_pacman(package=None):
    if package == None:
        sudo("pacman --noconfirm -Sy")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("pacman --noconfirm -S " + package)


def package_upgrade_pacman():
    sudo("pacman --noconfirm -Syu")


def package_install_pacman(package, update=False):
    if update:
        sudo("pacman --noconfirm -Sy")
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("pacman --noconfirm -S %s" % (package))


def package_ensure_pacman(package, update=False):
    """Ensure apt packages are installed"""
    if not isinstance(package, str):
        package = " ".join(package)
    status = run("pacman -Q %s ; true" % package)
    if ('was not found' in status):
        package_install_pacman(package, update)
        return False
    else:
        if update:
            package_update_pacman(package)
        return True


def package_clean_pacman():
    sudo("pacman --noconfirm -Sc")


def package_remove_pacman(package, autoclean=False):
    if autoclean:
        sudo('pacman --noconfirm -Rs ' + package)
    else:
        sudo('pacman --noconfirm -R ' + package)

# -----------------------------------------------------------------------------
# EMERGE PACKAGE (Gentoo Portage)
# added by davidmmiller - 20130417 - v0.1 (status - works for me...)
# -----------------------------------------------------------------------------


def repository_ensure_emerge(repository):
    raise Exception("Not implemented for emerge")
    """This will be used to add Portage overlays in a future update."""


def package_upgrade_emerge(distupgrade=False):
    sudo("emerge -q --update --deep --newuse --with-bdeps=y world")


def package_update_emerge(package=None):
    if package == None:
        sudo("emerge -q --sync")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("emerge -q --update --newuse %s" % package)


def package_install_emerge(package, update=False):
    if update:
        sudo("emerge -q --sync")
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("emerge -q %s" % (package))


def package_ensure_emerge(package, update=False):
    if not isinstance(package, str):
        package = " ".join(package)
    if update:
        sudo("emerge -q --update --newuse %s" % package)
    else:
        sudo("emerge -q --noreplace %s" % package)


def package_clean_emerge(package=None):
    if type(package) in (list, tuple):
        package = " ".join(package)
    if package:
        sudo("CONFIG_PROTECT='-*' emerge --quiet-unmerge-warn --unmerge %s" % package)
    else:
        sudo('emerge -q --depclean')
        sudo('revdep-rebuild -q')


def package_remove_emerge(package, autoclean=False):
    if autoclean:
        sudo('emerge --quiet-unmerge-warn --unmerge ' + package)
        sudo('emerge -q --depclean')
        sudo('revdep-rebuild -q')
    else:
        sudo('emerge --quiet-unmerge-warn --unmerge ' + package)

# -----------------------------------------------------------------------------
# PKGIN (Illumos, SmartOS, BSD, OSX)
# added by lbivens - 20130520 - v0.5 (this works but can be better)
# -----------------------------------------------------------------------------

# This should be simple but I have to think it properly


def repository_ensure_pkgin(repository):
    raise Exception("Not implemented for pkgin")


def package_upgrade_pkgin():
    sudo("pkgin -y upgrade")


def package_update_pkgin(package=None):
    # test if this works
    if package == None:
        sudo("pkgin -y update")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("pkgin -y upgrade " + package)


def package_install_pkgin(package, update=False):
    if update:
        sudo("pkgin -y update")
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("pkgin -y install %s" % (package))


def package_ensure_pkgin(package, update=False):
    # I am gonna have to do something different here
    status = run("pkgin list | grep %s ; true" % package)
    if status.find("No matching Packages") != -1 or status.find(package) == -1:
        package_install(package, update)
        return False
    else:
        if update:
            package_update(package)
        return True


def package_clean_pkgin(package=None):
    sudo("pkgin -y clean")


# -----------------------------------------------------------------------------
# PKG - FreeBSD
# -----------------------------------------------------------------------------

def repository_ensure_pkgng(repository):
    raise Exception("Not implemented for pkgng")


def package_upgrade_pkgng():
    sudo("echo y | pkg upgrade")


def package_update_pkgng(package=None):
    # test if this works
    if package == None:
        sudo("pkg -y update")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("pkg upgrade " + package)


def package_install_pkgng(package, update=False):
    if update:
        sudo("pkg update")
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("echo y | pkg install %s" % (package))


def package_ensure_pkgng(package, update=False):
    # I am gonna have to do something different here
    status = run("pkg info %s ; true" % package)
    if status.find("No package(s) matching") != -1 or status.find(package) == -1:
        package_install_pkgng(package, update)
        return False
    else:
        if update:
            package_update_pkgng(package)
        return True


def package_clean_pkgng(package=None):
    sudo("pkg delete %s" % (package))

# =============================================================================
#
# PYTHON PACKAGE OPERATIONS
#
# =============================================================================


@dispatch('python_package', multiple=True)
def python_package_upgrade(package):
    '''
    Upgrades the defined python package.
    '''


@dispatch('python_package', multiple=True)
def python_package_install(package=None):
    '''
    Installs the given python package/list of python packages.
    '''


@dispatch('python_package', multiple=True)
def python_package_ensure(package):
    '''
    Tests if the given python package is installed, and installes it in
    case it's not already there.
    '''


@dispatch('python_package', multiple=True)
def python_package_remove(package):
    '''
    Removes the given python package.
    '''

# -----------------------------------------------------------------------------
# PIP PYTHON PACKAGE MANAGER
# -----------------------------------------------------------------------------


def python_package_upgrade_pip(package, pip=None):
    '''
    The "package" argument, defines the name of the package that will be upgraded.
    '''
    pip = command("pip")
    run('%s install --upgrade %s' % (pip, package))


def python_package_install_pip(package=None, r=None, pip=None):
    '''
    The "package" argument, defines the name of the package that will be installed.
    The argument "r" referes to the requirements file that will be used by pip and
    is equivalent to the "-r" parameter of pip.
    Either "package" or "r" needs to be provided
    The optional argument "E" is equivalent to the "-E" parameter of pip. E is the
    path to a virtualenv. If provided, it will be added to the pip call.
    '''
    pip = command("pip")
    if package:
        run('%s install %s' % (pip, package))
    elif r:
        run('%s install -r %s' % (pip, r))
    else:
        raise Exception(
            "Either a package name or the requirements file has to be provided.")


def python_package_ensure_pip(package=None, r=None, pip=None):
    '''
    The "package" argument, defines the name of the package that will be ensured.
    The argument "r" referes to the requirements file that will be used by pip and
    is equivalent to the "-r" parameter of pip.
    Either "package" or "r" needs to be provided
    '''
    # FIXME: At the moment, I do not know how to check for the existence of a pip package and
    # I am not sure if this really makes sense, based on the pip built in functionality.
    # So I just call the install functions
    pip = command("pip")
    python_package_install_pip(package, r, pip)


def python_package_remove_pip(package, pip=None):
    '''
    The "package" argument, defines the name of the package that will be ensured.
    The argument "r" referes to the requirements file that will be used by pip and
    is equivalent to the "-r" parameter of pip.
    Either "package" or "r" needs to be provided
    '''
    pip = command("pip")
    return run('%s uninstall %s' % (pip, package))

# -----------------------------------------------------------------------------
# EASY_INSTALL PYTHON PACKAGE MANAGER
# -----------------------------------------------------------------------------


def python_package_upgrade_easy_install(package):
    '''
    The "package" argument, defines the name of the package that will be upgraded.
    '''
    run(f"{command('easy_install')} --upgrade '{package}")


def python_package_install_easy_install(package):
    '''
    The "package" argument, defines the name of the package that will be installed.
    '''
    run(f"{command('easy_install')} '{package}")


def python_package_ensure_easy_install(package):
    '''
    The "package" argument, defines the name of the package that will be ensured.
    '''
    # FIXME: At the moment, I do not know how to check for the existence of a py package and
    # I am not sure if this really makes sense, based on the easy_install built in functionality.
    # So I just call the install functions
    python_package_install_easy_install(package)


def python_package_remove_easy_install(package):
    '''
    The "package" argument, defines the name of the package that will be removed.
    '''
    # FIXME: this will not remove egg file etc.
    run(f"{command('easy_install')} -m '{package}")

# =============================================================================
#
# SHELL COMMANDS
#
# =============================================================================


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

# =============================================================================
#
# USER OPERATIONS
#
# =============================================================================


@dispatch('user')
def user_passwd(name, passwd, encrypted_passwd=True):
    """Sets the given user password. Password is expected to be encrypted by default."""


@dispatch('user')
def user_create(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""


@dispatch('user')
def user_check(name=None, uid=None, need_passwd=True):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists.
    need_passwd (Boolean) indicates if password to be included in result or not.
            If set to True it parses 'getent shadow' and needs sudo access
    """


@dispatch('user')
def user_ensure(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""


@dispatch('user')
def user_remove(name, rmhome=None):
    """Removes the user with the given name, optionally
    removing the home directory and mail spool."""

# =============================================================================
# Linux support (useradd, usermod)
# =============================================================================


def user_passwd_linux(name, passwd, encrypted_passwd=True):
    """Sets the given user password. Password is expected to be encrypted by default."""
    encoded_password = base64.b64encode("%s:%s" % (name, passwd))
    if encrypted_passwd:
        sudo("usermod -p '%s' %s" % (passwd, name))
    else:
        # NOTE: We use base64 here in case the password contains special chars
        # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
        sudo("echo %s | openssl base64 -A -d | chpasswd" %
             (shell_safe(encoded_password)))


def user_create_linux(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                      uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u '%s'" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-K UID_MIN='%s'" % (uid_min))
    if uid_max:
        options.append("-K UID_MAX='%s'" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("useradd %s '%s'" % (" ".join(options), name))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


@ requires(commands=("pw",))
def user_create_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                    uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u %s" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-u %s," % (uid_min))
    if uid_max:
        options.append("%s" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("pw useradd -n %s %s" % (name, " ".join(options)))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


@ requires(commands=("getent", "egrep", "true", "awk"))
def user_check_linux(name=None, uid=None, need_passwd=True):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists.
    need_passwd (Boolean) indicates if password to be included in result or not.
            If set to True it parses 'getent shadow' and needs sudo access
    """
    assert name != None or uid != None,     "user_check: either `uid` or `name` should be given"
    assert name is None or uid is None, "user_check: `uid` and `name` both given, only one should be provided"
    if name != None:
        d = run("getent passwd | egrep '^%s:' ; true" % (name))
    elif uid != None:
        d = run("getent passwd | egrep '^.*:.*:%s:' ; true" % (uid))
    results = {}
    s = None
    if d:
        d = d.split(":")
        assert len(d) >= 7, "passwd entry returned by getent is expected to have at least 7 fields, got %s in: %s" % (
            len(d), ":".join(d))
        results = dict(name=d[0], uid=d[2], gid=d[3],
                       fullname=d[4], home=d[5], shell=d[6])
        if need_passwd:
            s = sudo(
                "getent shadow | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
            if s:
                results['passwd'] = s
    if results:
        return results
    else:
        return None


def user_ensure_linux(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""
    d = user_check(name)
    if not d:
        user_create(name, passwd, home, uid, gid, shell,
                    fullname=fullname, encrypted_passwd=encrypted_passwd)
    else:
        options = []
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if fullname != None and d.get("fullname") != fullname:
            options.append("-c '%s'" % fullname)
        if options:
            sudo("usermod %s '%s'" % (" ".join(options), name))
        if passwd:
            user_passwd(name=name, passwd=passwd,
                        encrypted_passwd=encrypted_passwd)


def user_remove_linux(name, rmhome=None):
    """Removes the user with the given name, optionally
    removing the home directory and mail spool."""
    options = ["-f"]
    if rmhome:
        options.append("-r")
    sudo("userdel %s '%s'" % (" ".join(options), name))

# =============================================================================
# BSD support (pw useradd, userdel )
# =============================================================================


def user_passwd_bsd(name, passwd, encrypted_passwd=True):
    """Sets the given user password. Password is expected to be encrypted by default."""
    encoded_password = base64.b64encode("%s:%s" % (name, passwd))
    if encrypted_passwd:
        sudo("pw usermod '%s' -p %s" % (name, passwd))
    else:
        # NOTE: We use base64 here in case the password contains special chars
        # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
        sudo("echo %s | openssl base64 -A -d | chpasswd" %
             (shell_safe(encoded_password)))


def user_create_passwd_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                           uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u '%s'" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-K UID_MIN='%s'" % (uid_min))
    if uid_max:
        options.append("-K UID_MAX='%s'" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("useradd %s '%s'" % (" ".join(options), name))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


def user_create_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                    uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u %s" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-u %s," % (uid_min))
    if uid_max:
        options.append("%s" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("pw useradd -n %s %s" % (name, " ".join(options)))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


def user_check_bsd(name=None, uid=None, need_passwd=True):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists.
    need_passwd (Boolean) indicates if password to be included in result or not.
            If set to True it parses 'getent passwd' and needs sudo access
    """
    assert name != None or uid != None,     "user_check: either `uid` or `name` should be given"
    assert name is None or uid is None, "user_check: `uid` and `name` both given, only one should be provided"
    if name != None:
        d = run("getent passwd | egrep '^%s:' ; true" % (name))
    elif uid != None:
        d = run("getent passwd | egrep '^.*:.*:%s:' ; true" % (uid))
    results = {}
    s = None
    if d:
        d = d.split(":")
        assert len(d) >= 7, "passwd entry returned by getent is expected to have at least 7 fields, got %s in: %s" % (
            len(d), ":".join(d))
        results = dict(name=d[0], uid=d[2], gid=d[3],
                       fullname=d[4], home=d[5], shell=d[6])
        if need_passwd:
            s = sudo(
                "getent passwd | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
            if s:
                results['passwd'] = s
    if results:
        return results
    else:
        return None


def user_ensure_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""
    d = user_check(name)
    if not d:
        user_create(name, passwd, home, uid, gid, shell,
                    fullname=fullname, encrypted_passwd=encrypted_passwd)
    else:
        options = []
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if fullname != None and d.get("fullname") != fullname:
            options.append("-c '%s'" % fullname)
        if options:
            sudo("pw usermod %s '%s'" % (name, " ".join(options)))
        if passwd:
            user_passwd(name=name, passwd=passwd,
                        encrypted_passwd=encrypted_passwd)


def user_remove_bsd(name, rmhome=None):
    """Removes the user with the given name, optionally
    removing the home directory and mail spool."""
    options = ["-f"]
    if rmhome:
        options.append("-r")
    sudo("pw userdel %s '%s'" % (" ".join(options), name))

# =============================================================================
#
# GROUP OPERATIONS
#
# =============================================================================


@dispatch('group')
def group_create(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""


@dispatch('group')
def group_check(name):
    """Checks if there is a group defined with the given name,
    returning its information as a
    '{"name":<str>,"gid":<str>,"members":<list[str]>}' or 'None' if
    the group does not exists."""


@dispatch('group')
def group_ensure(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""


@dispatch('group')
def group_user_check(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""


@dispatch('group')
def group_user_add(group, user):
    """Adds the given user/list of users to the given group/groups."""


@dispatch('group')
def group_user_ensure(group, user):
    """Ensure that a given user is a member of a given group."""


@dispatch('group')
def group_user_del(group, user):
    """remove the given user from the given group."""


@dispatch('group')
def group_remove(group=None, wipe=False):
    """ Removes the given group, this implies to take members out the group
    if there are any.  If wipe=True and the group is a primary one,
    deletes its user as well.
    """

# Linux support
#
# =============================================================================


def group_create_linux(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""
    options = []
    if gid:
        options.append("-g '%s'" % (gid))
    sudo("groupadd %s '%s'" % (" ".join(options), name))


def group_check_linux(name):
    """Checks if there is a group defined with the given name,
    returning its information as:
    '{"name":<str>,"gid":<str>,"members":<list[str]>}'
    or
    '{"name":<str>,"gid":<str>}' if the group has no members
    or
    'None' if the group does not exists."""
    group_data = run("getent group | egrep '^%s:' ; true" % (name))
    if len(group_data.split(":")) == 4:
        name, _, gid, members = group_data.split(":", 4)
        return dict(name=name, gid=gid,
                    members=tuple(m.strip() for m in members.split(",")))
    elif len(group_data.split(":")) == 3:
        name, _, gid = group_data.split(":", 3)
        return dict(name=name, gid=gid, members=(''))
    else:
        return None


def group_ensure_linux(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""
    d = group_check(name)
    if not d:
        group_create(name, gid)
    else:
        if gid != None and d.get("gid") != gid:
            sudo("groupmod -g %s '%s'" % (gid, name))


def group_user_check_linux(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""
    d = group_check(group)
    if d is None:
        return False
    else:
        return user in d["members"]


def group_user_add_linux(group, user):
    """Adds the given user/list of users to the given group/groups."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if not group_user_check(group, user):
        sudo("usermod -a -G '%s' '%s'" % (group, user))


def group_user_ensure_linux(group, user):
    """Ensure that a given user is a member of a given group."""
    d = group_check(group)
    if not d:
        group_ensure("group")
        d = group_check(group)
    if user not in d["members"]:
        group_user_add(group, user)


def group_user_del_linux(group, user):
    """remove the given user from the given group."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if group_user_check(group, user):
        group_for_user = run(
            "getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
        if group_for_user:
            sudo("usermod -G '%s' '%s'" % (",".join(group_for_user), user))
        else:
            sudo("usermod -G '' '%s'" % (user))


def group_remove_linux(group=None, wipe=False):
    """ Removes the given group, this implies to take members out the group
    if there are any.  If wipe=True and the group is a primary one,
    deletes its user as well.
    """
    assert group_check(group), "Group does not exist: %s" % (group)
    members_of_group = run("getent group %s | awk -F':' '{print $4}'" % group)
    members = members_of_group.split(",")
    is_primary_group = user_check(name=group)
    if wipe:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        if is_primary_group:
            user_remove(group)
        else:
            sudo("groupdel %s" % group)
    elif not is_primary_group:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        sudo("groupdel %s" % group)


# =============================================================================
#
# BSD support
#
# =============================================================================

def group_create_bsd(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""
    options = []
    if gid:
        options.append("-g '%s'" % (gid))
    sudo("pw groupadd %s -n %s" % (" ".join(options), name))


def group_check_bsd(name):
    """Checks if there is a group defined with the given name,
    returning its information as:
    '{"name":<str>,"gid":<str>,"members":<list[str]>}'
    or
    '{"name":<str>,"gid":<str>}' if the group has no members
    or
    'None' if the group does not exists."""
    group_data = run("getent group | egrep '^%s:' ; true" % (name))
    if len(group_data.split(":")) == 4:
        name, _, gid, members = group_data.split(":", 4)
        return dict(name=name, gid=gid,
                    members=tuple(m.strip() for m in members.split(",")))
    elif len(group_data.split(":")) == 3:
        name, _, gid = group_data.split(":", 3)
        return dict(name=name, gid=gid, members=(''))
    else:
        return None


def group_ensure_bsd(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""
    d = group_check(name)
    if not d:
        group_create(name, gid)
    else:
        if gid != None and d.get("gid") != gid:
            sudo("pw groupmod -g %s -n %s" % (gid, name))


def group_user_check_bsd(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""
    d = group_check(group)
    if d is None:
        return False
    else:
        return user in d["members"]


def group_user_add_bsd(group, user):
    """Adds the given user/list of users to the given group/groups."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if not group_user_check(group, user):
        sudo("pw usermod '%s' -G '%s'" % (user, group))


def group_user_ensure_bsd(group, user):
    """Ensure that a given user is a member of a given group."""
    d = group_check(group)
    if not d:
        group_ensure("group")
        d = group_check(group)
    if user not in d["members"]:
        group_user_add(group, user)


def group_user_del_bsd(group, user):
    """remove the given user from the given group."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if group_user_check(group, user):
        group_for_user = run(
            "getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
        if group_for_user:
            sudo("pw usermod -G '%s' '%s'" % (",".join(group_for_user), user))
        else:
            sudo("pw usermod -G '' '%s'" % (user))


def group_remove_bsd(group=None, wipe=False):
    """ Removes the given group, this implies to take members out the group
    if there are any.  If wipe=True and the group is a primary one,
    deletes its user as well.
    """
    assert group_check(group), "Group does not exist: %s" % (group)
    members_of_group = run("getent group %s | awk -F':' '{print $4}'" % group)
    members = members_of_group.split(",")
    is_primary_group = user_check(name=group)

    if wipe:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        if is_primary_group:
            user_remove(group)
        else:
            sudo("pw groupdel %s" % group)

    elif not is_primary_group:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        sudo("pw groupdel %s" % group)

# =============================================================================
#
# SSH
#
# =============================================================================


def ssh_keygen(user, keytype="dsa"):
    """Generates a pair of ssh keys in the user's home .ssh directory."""
    d = user_check(user)
    assert d, "User does not exist: %s" % (user)
    home = d["home"]
    key_file = home + "/.ssh/id_%s.pub" % keytype
    if not file_exists(key_file):
        dir_ensure(home + "/.ssh", mode="0700", owner=user, group=user)
        run("ssh-keygen -q -t %s -f '%s/.ssh/id_%s' -N ''" %
            (keytype, home, keytype))
        file_attribs(home + "/.ssh/id_%s" % keytype, owner=user, group=user)
        file_attribs(home + "/.ssh/id_%s.pub" %
                     keytype, owner=user, group=user)
        return key_file
    else:
        return key_file


def ssh_authorize(user, key):
    """Adds the given key to the '.ssh/authorized_keys' for the given
    user."""
    d = user_check(user, need_passwd=False)
    group = d["gid"]
    keyf = d["home"] + "/.ssh/authorized_keys"
    if key[-1] != "\n":
        key += "\n"
    if file_exists(keyf):
        d = file_read(keyf)
        if file_read(keyf).find(key[:-1]) == -1:
            file_append(keyf, key)
            return False
        else:
            return True
    else:
        # Make sure that .ssh directory exists, see #42
        dir_ensure(os.path.dirname(keyf), owner=user, group=group, mode="700")
        file_write(keyf, key,             owner=user, group=group, mode="600")
        return False


def ssh_unauthorize(user, key):
    """Removes the given key to the remote '.ssh/authorized_keys' for the given
    user."""
    key = key.strip()
    d = user_check(user, need_passwd=False)
    group = d["gid"]
    keyf = d["home"] + "/.ssh/authorized_keys"
    if file_exists(keyf):
        file_write(keyf, "\n".join(_ for _ in file_read(keyf).split(
            "\n") if _.strip() != key), owner=user, group=group, mode="600")
        return True
    else:
        return False


# =============================================================================
#
# SYSTEM
#
# =============================================================================

def system_uuid_alias_add():
    """Adds system UUID alias to /etc/hosts.
    Some tools/processes rely/want the hostname as an alias in
    /etc/hosts e.g. `127.0.0.1 localhost <hostname>`.
    """
    with mode_sudo():
        old = "127.0.0.1 localhost"
        new = old + " " + system_uuid()
        file_update('/etc/hosts', lambda x: text_replace_line(x, old, new)[0])


def system_uuid():
    """Gets a machines UUID (Universally Unique Identifier)."""
    return sudo('dmidecode -s system-uuid | tr "[A-Z]" "[a-z]"')

# =============================================================================
#
# RSYNC
#
# =============================================================================


def rsync(local_path: str, remote_path: str, compress: bool = True, progress: bool = False, verbose: bool = True, owner: bool = None, group: bool = None):
    """Rsyncs local to remote, using the connection's host and user."""
    options = "-a"
    if compress:
        options += "z"
    if verbose:
        options += "v"
    if progress:
        options += " --progress"
    if owner or group:
        assert owner and group or not owner
        options += " --chown={0}{1}".format(owner or "",
                                            ":" + group if group else "")
    with mode_local():
        run("rsync {options} {local} {user}@{host}:{remote}".format(
            options=options,
            host=host(),
            user=user(),
            local=local_path,
            remote=remote_path,
        ))

# =============================================================================
#
# LOCALE
#
# =============================================================================


def locale_check(locale):
    locale_data = sudo("locale -a | egrep '^%s$' ; true" % (locale,))
    return locale_data == locale


def locale_ensure(locale):
    if not locale_check(locale):
        with fabric.context_managers.settings(warn_only=True):
            sudo("/usr/share/locales/install-language-pack %s" % (locale,))
        sudo("dpkg-reconfigure locales")

# Sets up the default options so that @dispatch'ed functions work

# =============================================================================
#
# REQUIRE
#
# =============================================================================


def require_package(package: str) -> bool:
    """Ensures that the given package is available and installed"""
    if not package_available(package):
        fail(f"Package not available: {package}")
    if not package_installed(package):
        if not package_install(package):
            fail(f"Unable to install package: {package}")
    return True


# =============================================================================
#
# STATUS
#
# =============================================================================


def fail(message):
    log_error(message)
    # TODO: Should set the result of the session as failure
    raise NotImplementedError


def _init():
    # NOTE: Removed from now as is seems to cause problems #188
    # # If we don't find a host, we setup the local mode
    # if not env_.host_string: mode_local()
    # We set the default options
    for option, value in DEFAULT_OPTIONS.items():
        eval("select_" + option)(value)


_init()

# EOF
