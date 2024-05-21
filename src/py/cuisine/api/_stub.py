from typing import Tuple, List, Dict, Optional, Union, ForwardRef, ContextManager
import cuisine.connection
import pathlib
# NOTE: This is automatically generated by `python -m cuisine.api -t stub`, do not edit
class API:

     def command(self, name: str) -> str:
          """Returns the normalized command name. This first tries to find a match
        in `DEFAULT_COMMANDS` and extract it, and then look for a `COMMAND_{name}`
        in the environment."""
          raise NotImplementedError

     def command_check(self, command: str) -> bool:
          """Tests if the given command is available on the system."""
          raise NotImplementedError

     def command_ensure(self, command: str, package=None) -> bool:
          """Ensures that the given command is present, if not installs the
        package with the given name, which is the same as the command by
        default."""
          raise NotImplementedError

     def config_clear(self, variable: str) -> Optional[str]:
          """Clears the given `variable` from connection's environment.
        `default` if not found."""
          raise NotImplementedError

     def config_get(self, variable: str, default: Optional[str] = None) -> Optional[str]:
          """Returns the given `variable` from the connection's environment, returning
        `default` if not found."""
          raise NotImplementedError

     def config_get_variant(self, group: str) -> Optional[str]:
          """None"""
          raise NotImplementedError

     def config_has(self, variable: str) -> bool:
          """Sets the given `variable` in the connection's environment, returning
        `default` if not found."""
          raise NotImplementedError

     def config_set(self, variable: str, value: str) -> str:
          """Sets the given `variable` in the connection's environment, returning
        `default` if not found."""
          raise NotImplementedError

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
          raise NotImplementedError

     def connect(self, host=None, port=None, user=None, password=None, key: Union[str, pathlib.Path] = None, transport: Optional[str] = None) -> ContextManager:
          """Connects to the given host/port using the given user/password/key_path credentials. Note that
        not all connection types support all these arguments, so you might get warnings if they are
        not supported."""
          raise NotImplementedError

     def connect_local(self, user=None) -> ContextManager:
          """None"""
          raise NotImplementedError

     def connect_mitogen(self, host=None, port=None, user=None, password=None, key: Optional[pathlib.Path] = None) -> ContextManager:
          """None"""
          raise NotImplementedError

     def connect_parallelssh(self, host=None, port=None, user=None, password=None, key: Optional[pathlib.Path] = None) -> ContextManager:
          """None"""
          raise NotImplementedError

     def connect_paramiko(self, host=None, port=None, user=None, password=None, key: Optional[pathlib.Path] = None) -> ContextManager:
          """None"""
          raise NotImplementedError

     def connect_tmux(self, session: str, window: str) -> ContextManager:
          """Creates a new connection using the TmuxConnection"""
          raise NotImplementedError

     def connection(self) -> cuisine.connection.Connection:
          """Returns the current connection"""
          raise NotImplementedError

     def connection_like(self, predicate) -> Optional[cuisine.connection.Connection]:
          """Returns the most recent opened connection that matches the given
        predicate."""
          raise NotImplementedError

     def detect_connection(self) -> str:
          """Detects the recommended type of connection"""
          raise NotImplementedError

     def disconnect(self) -> Optional[cuisine.connection.Connection]:
          """Disconnects from the current connection unless it'"s the default
        local connection."""
          raise NotImplementedError

     def fail(self, message: Optional[str] = None):
          """None"""
          raise NotImplementedError

     def is_local(self) -> bool:
          """Tells if the current connection is local or not."""
          raise NotImplementedError

     def run(self, command: str) -> 'CommandOutput':
          """None"""
          raise NotImplementedError

     def run_local(self, command: str) -> 'CommandOutput':
          """None"""
          raise NotImplementedError

     def select_connection(self, type: str) -> bool:
          """Selects the default type of connection. This returns `False` in case
        the connection is not found."""
          raise NotImplementedError

     def sudo(self, command: Optional[str] = None) -> Union[ContextManager, ForwardRef('CommandOutput')]:
          """None"""
          raise NotImplementedError

     def terminate(self) -> List[cuisine.connection.Connection]:
          """Terminates/disconnects any remaining connection"""
          raise NotImplementedError

     def dir_attribs(self, path: str, mode=None, owner=None, group=None, recursive=False):
          """Updates the mode/owner/group for the given remote directory."""
          raise NotImplementedError

     def dir_ensure(self, path: str, recursive=True, mode=None, owner=None, group=None) -> str:
          """Ensures that there is a remote directory at the given path,
        optionally updating its mode/owner/group.

        If we are not updating the owner/group then this can be done as a single
        ssh call, so use that method, otherwise set owner/group after creation."""
          raise NotImplementedError

     def dir_ensure_parent(self, path: str, recursive=True, mode=None, owner=None, group=None):
          """Ensures that the parent directory of the given path exists"""
          raise NotImplementedError

     def dir_exists(self, path: str) -> bool:
          """Tells if there is a remote directory at the given path."""
          raise NotImplementedError

     def dir_remove(self, path: str, recursive=True) -> Optional[bool]:
          """ Removes a directory """
          raise NotImplementedError

     def env_clear(self, variable: str) -> str:
          """Clears the given `variable` from connection's environment.
        `default` if not found."""
          raise NotImplementedError

     def env_get(self, variable: str, default: Optional[str] = None) -> str:
          """Returns the given `variable` from the connection's environment, returning
        `default` if not found."""
          raise NotImplementedError

     def env_set(self, variable: str, value: str) -> str:
          """Sets the given `variable` in the connection's environment, returning
        `default` if not found."""
          raise NotImplementedError

     def file_append(self, path: str, content: Union[bytes, str], mode: Optional[str] = None, owner: Optional[str] = None, group: Optional[str] = None):
          """Appends the given content to the remote file at the given
        path, optionally updating its mode/owner/group."""
          raise NotImplementedError

     def file_attribs(self, path: str, mode=None, owner=None, group=None):
          """Updates the mode/owner/group for the remote file at the given
        path."""
          raise NotImplementedError

     def file_attribs_get(self, path: str) -> Dict[str, str]:
          """Return mode, owner, and group for remote path.
        Return mode, owner, and group if remote path exists, 'None'
        otherwise.
        """
          raise NotImplementedError

     def file_backup(self, path: str, suffix='.orig', once=False):
          """Backups the file at the given path in the same directory, appending
        the given suffix. If `once` is True, then the backup will be skipped if
        there is already a backup file."""
          raise NotImplementedError

     def file_base64(self, path: str) -> str:
          """Returns the base64-encoded content of the file at the given path."""
          raise NotImplementedError

     def file_download(self, remote: str, local: str, mode: Optional[int] = None, owner: Optional[str] = None, group: Optional[str] = None):
          """Downloads the file at the `remote` path to the `local` path."""
          raise NotImplementedError

     def file_ensure(self, path, mode=None, owner=None, group=None, scp=False):
          """Updates the mode/owner/group for the remote file at the given
        path."""
          raise NotImplementedError

     def file_ensure_lines(self, path: str, lines: list[str], mode=None, owner=None, group=None):
          """Updates the mode/owner/group for the remote file at the given
        path."""
          raise NotImplementedError

     def file_exists(self, path: str) -> bool:
          """Tests if there is a *remote* file at the given path."""
          raise NotImplementedError

     def file_is_dir(self, path: str) -> bool:
          """Tells if the given path is a directory or not"""
          raise NotImplementedError

     def file_is_file(self, path: str):
          """Tells if the given path is a file or not"""
          raise NotImplementedError

     def file_is_link(self, path: str) -> bool:
          """Tells if the given path is a symlink or not"""
          raise NotImplementedError

     def file_link(self, source, destination, symbolic=True, mode=None, owner=None, group=None):
          """Creates a (symbolic) link between source and destination on the remote host,
        optionally setting its mode/owner/group."""
          raise NotImplementedError

     def file_md5(self, path: str):
          """Returns the MD5 sum (as a hex string) for the remote file at the given path."""
          raise NotImplementedError

     def file_name(self, path: str) -> str:
          """Returns the file name for the given path."""
          raise NotImplementedError

     def file_read(self, path: str) -> bytes:
          """Reads the *remote* file at the given path, if default is not `None`,
        default will be returned if the file does not exist."""
          raise NotImplementedError

     def file_read_str(self, path: str) -> str:
          """None"""
          raise NotImplementedError

     def file_sha256(self, path: str):
          """Returns the SHA-256 sum (as a hex string) for the remote file at the given path."""
          raise NotImplementedError

     def file_unlink(self, path: str):
          """Removes the given file path if it exists"""
          raise NotImplementedError

     def file_update(self, path: str, updater=None):
          """Updates the content of the given by passing the existing
        content of the remote file at the given path to the 'updater'
        function. Return true if file content was changed.

        For instance, if you'd like to convert an existing file to all
        uppercase, simply do:

        >   file_update("/etc/myfile", lambda _:_.upper())

        Or restart service on config change:

        >   if file_update("/etc/myfile.cfg", lambda _: text_ensure_line(_, line)): run("service restart")
        """
          raise NotImplementedError

     def file_upload(self, local: str, remote: str, mode: Optional[str] = None, owner: Optional[str] = None, group: Optional[str] = None):
          """Downloads the local file to the remote path only if the remote path does not
        exists or the content are different."""
          raise NotImplementedError

     def file_write(self, path: str, content: Union[str, bytes], mode=None, owner=None, group=None, sudo=None, check=True, scp=False):
          """Writes the given content to the file at the given remote
        path, optionally setting mode/owner/group."""
          raise NotImplementedError

     def user_create_linux(self, name: str, passwd: Optional[str] = None, home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None, shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None, encrypted_passwd: Optional[bool] = True, fullname: Optional[str] = None, create_home: Optional[bool] = True):
          """None"""
          raise NotImplementedError

     def user_ensure_linux(self, name: str, passwd: Optional[str] = None, home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None, shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None, encrypted_passwd: Optional[bool] = True, fullname: Optional[str] = None, create_home: Optional[bool] = True):
          """None"""
          raise NotImplementedError

     def user_exists_linux(self, name: str) -> bool:
          """None"""
          raise NotImplementedError

     def user_get_linux(self, name: str = None, uid: int = None):
          """None"""
          raise NotImplementedError

     def user_passwd_linux(self, name: str, passwd: str, encrypted_passwd=True):
          """Sets the given user password. Password is expected to be encrypted by default."""
          raise NotImplementedError

     def user_remove_linux(self, name: str, remove_home: bool = False):
          """Removes the user with the given name, optionally
        removing the home directory and mail spool."""
          raise NotImplementedError

     def error(self, message: str) -> None:
          """None"""
          raise NotImplementedError

     def info(self, message: str) -> None:
          """None"""
          raise NotImplementedError

     def detect_package(self) -> str:
          """Automatically detects the type of package"""
          raise NotImplementedError

     def package_available(self, package: str) -> bool:
          """Tells if the given package is available"""
          raise NotImplementedError

     def package_clean(self, package=None):
          """Clean the repository for un-needed files."""
          raise NotImplementedError

     def package_ensure(self, package, update=False):
          """Tests if the given package is installed, and installs it in
        case it's not already there. If `update` is true, then the
        package will be updated if it already exists."""
          raise NotImplementedError

     def package_install(self, package, update=False):
          """Installs the given package/list of package, optionally updating
        the package database."""
          raise NotImplementedError

     def package_installed(self, package, update=False) -> bool:
          """Tells if the given package is installed or not."""
          raise NotImplementedError

     def package_remove(self, package, autoclean=False):
          """Remove package and optionally clean unused packages"""
          raise NotImplementedError

     def package_update(self, package=None):
          """Updates the package database (when no argument) or update the package
        or list of packages given as argument."""
          raise NotImplementedError

     def package_upgrade(self, distupgrade=False):
          """Updates every package present on the system."""
          raise NotImplementedError

     def select_package(self, type: str) -> bool:
          """None"""
          raise NotImplementedError

     def package_available_apt(package: str) -> bool:
          """None"""
          raise NotImplementedError

     def package_clean_apt(self, package=None):
          """None"""
          raise NotImplementedError

     def package_ensure_apt(self, package, update=False):
          """Ensure apt packages are installed"""
          raise NotImplementedError

     def package_install_apt(self, package, update=False):
          """None"""
          raise NotImplementedError

     def package_installed_apt(self, package, update=False) -> False:
          """None"""
          raise NotImplementedError

     def package_remove_apt(self, package, autoclean=False):
          """None"""
          raise NotImplementedError

     def package_update_apt(self, package=None):
          """None"""
          raise NotImplementedError

     def package_upgrade_apt(self, distupgrade=False):
          """None"""
          raise NotImplementedError

     def repository_ensure_apt(self, repository):
          """None"""
          raise NotImplementedError

     def package_clean_yum(self, package=None):
          """None"""
          raise NotImplementedError

     def package_ensure_yum(self, package, update=False):
          """None"""
          raise NotImplementedError

     def package_install_yum(self, package, update=False):
          """None"""
          raise NotImplementedError

     def package_remove_yum(self, package, autoclean=False):
          """None"""
          raise NotImplementedError

     def package_update_yum(self, package=None):
          """None"""
          raise NotImplementedError

     def package_upgrade_yum():
          """None"""
          raise NotImplementedError

     def repository_ensure_yum(self, repository: str):
          """None"""
          raise NotImplementedError

     def python_package_ensure_pip(self, package=None, local=True):
          """None"""
          raise NotImplementedError

     def python_package_install_pip(self, package=None, local=True):
          """None"""
          raise NotImplementedError

     def python_package_remove_pip(self, package, local=True):
          """None"""
          raise NotImplementedError

     def python_package_upgrade_pip(self, package=None, local=True):
          """None"""
          raise NotImplementedError

     def detect_python_package(self) -> str:
          """Automatically detects the type of package"""
          raise NotImplementedError

     def python_package_ensure(self, package):
          """Tests if the given python package is installed, and installs it in
        case it's not already there."""
          raise NotImplementedError

     def python_package_install(self, package=None):
          """Installs the given python package/list of python packages."""
          raise NotImplementedError

     def python_package_remove(self, package):
          """Removes the given python package. """
          raise NotImplementedError

     def python_package_upgrade(self, package):
          """Upgraded the given Python package"""
          raise NotImplementedError

     def select_python_package(self, type: str) -> bool:
          """None"""
          raise NotImplementedError

     def ssh_authorize(self, user: str, key: Optional[str] = None) -> bool:
          """Adds the given key to the '.ssh/authorized_keys' for the given
        user."""
          raise NotImplementedError

     def ssh_keygen(self, user: str, keytype='rsa') -> str:
          """Generates a pair of ssh keys in the user's home .ssh directory."""
          raise NotImplementedError

     def ssh_unauthorize(self, user: str, key: str):
          """Removes the given key to the remote '.ssh/authorized_keys' for the given
        user."""
          raise NotImplementedError

     def tmux_has(self, session: str, window: Optional[int]) -> bool:
          """None"""
          raise NotImplementedError

     def tmux_is_responsive(self, session: str, window: int) -> Optional[bool]:
          """None"""
          raise NotImplementedError

     def tmux_session_list(self) -> List[str]:
          """None"""
          raise NotImplementedError

     def tmux_window_list(self, session: str) -> List[int]:
          """None"""
          raise NotImplementedError

     def detect_user(self) -> str:
          """None"""
          raise NotImplementedError

     def user_create(self, name: str, passwd: Optional[str] = None, home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None, shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None, encrypted_passwd: Optional[bool] = True, fullname: Optional[str] = None, create_home: Optional[bool] = True):
          """Creates the user with the given name, optionally giving a
        specific password/home/uid/gid/shell."""
          raise NotImplementedError

     def user_ensure(self, name: str, passwd: Optional[str] = None, home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None, shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None, encrypted_passwd: Optional[bool] = True, fullname: Optional[str] = None, create_home: Optional[bool] = True):
          """Ensures that the given users exists, optionally updating their
        passwd/home/uid/gid/shell."""
          raise NotImplementedError

     def user_exists(self, name: str) -> bool:
          """Tells if the user exists."""
          raise NotImplementedError

     def user_get(self, name: Optional[str] = None, uid: Optional[int] = None) -> Dict:
          """Checks if there is a user defined with the given name,
        returning its information as a
        '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
        or 'None' if the user does not exists.
        need_passwd (Boolean) indicates if password to be included in result or not.
                If set to True it parses 'getent shadow' and needs sudo access
        """
          raise NotImplementedError

     def user_passwd(self, name: str, passwd: str, encrypted_passwd=True):
          """Sets the given user password. Password is expected to be encrypted by default."""
          raise NotImplementedError

     def user_remove(self, name: str, remove_home: bool = False):
          """Removes the user with the given name, optionally
        removing the home directory and mail spool."""
          raise NotImplementedError

# EOF