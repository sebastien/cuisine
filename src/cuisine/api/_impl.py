from .._stub import API as APIInterface
class API(APIInterface):

     def __init__(self):
          import cuisine.api.dir as cuisine_api_dir
          import cuisine.api.file as cuisine_api_file
          self._dirapi = cuisine_api_dir.DirAPI(self)
          self._fileapi = cuisine_api_file.FileAPI(self)

     def dir_attribs(self, path: str, mode=None, owner=None, group=None, recursive=False):
          """Updates the mode/owner/group for the given remote directory."""
          return self._dir.dir_attribs(self, path, mode, owner, group, recursive)

     def dir_ensure(self, path: str, recursive=True, mode=None, owner=None, group=None) -> str:
          """Ensures that there is a remote directory at the given path,
        optionally updating its mode/owner/group.

        If we are not updating the owner/group then this can be done as a single
        ssh call, so use that method, otherwise set owner/group after creation."""
          return self._dir.dir_ensure(self, path, recursive, mode, owner, group)

     def dir_ensure_parent(self, path: str):
          """Ensures that the parent directory of the given path exists"""
          return self._dir.dir_ensure_parent(self, path)

     def dir_exists(self, path: str) -> bool:
          """Tells if there is a remote directory at the given path."""
          return self._dir.dir_exists(self, path)

     def dir_remove(self, path: str, recursive=True):
          """ Removes a directory """
          return self._dir.dir_remove(self, path, recursive)

     def file_append(self, path, content, mode=None, owner=None, group=None):
          """Appends the given content to the remote file at the given
        path, optionally updating its mode/owner/group."""
          return self._file.file_append(self, path, content, mode, owner, group)

     def file_attribs_get(self, path):
          """Return mode, owner, and group for remote path.
        Return mode, owner, and group if remote path exists, 'None'
        otherwise.
        """
          return self._file.file_attribs_get(self, path)

     def file_backup(self, path: str, suffix='.orig', once=False):
          """Backups the file at the given path in the same directory, appending
        the given suffix. If `once` is True, then the backup will be skipped if
        there is already a backup file."""
          return self._file.file_backup(self, path, suffix, once)

     def file_base64(self, path: str):
          """Returns the base64-encoded content of the file at the given path."""
          return self._file.file_base64(self, path)

     def file_ensure(self, path, mode=None, owner=None, group=None, scp=False):
          """Updates the mode/owner/group for the remote file at the given
        path."""
          return self._file.file_ensure(self, path, mode, owner, group, scp)

     def file_exists(self, path):
          """Tests if there is a *remote* file at the given path."""
          return self._file.file_exists(self, path)

     def file_is_dir(self, path: str) -> bool:
          """None"""
          return self._file.file_is_dir(self, path)

     def file_is_file(self, path):
          """None"""
          return self._file.file_is_file(self, path)

     def file_is_link(self, path: str) -> bool:
          """None"""
          return self._file.file_is_link(self, path)

     def file_link(self, source, destination, symbolic=True, mode=None, owner=None, group=None):
          """Creates a (symbolic) link between source and destination on the remote host,
        optionally setting its mode/owner/group."""
          return self._file.file_link(self, source, destination, symbolic, mode, owner, group)

     def file_md5(self, path: str):
          """Returns the MD5 sum (as a hex string) for the remote file at the given path."""
          return self._file.file_md5(self, path)

     def file_name(self, path: str) -> str:
          """Returns the file name for the given path."""
          return self._file.file_name(self, path)

     def file_read(self, path, default=None):
          """Reads the *remote* file at the given path, if default is not `None`,
        default will be returned if the file does not exist."""
          return self._file.file_read(self, path, default)

     def file_unlink(self, path: str):
          """None"""
          return self._file.file_unlink(self, path)

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
          return self._file.file_update(self, path, updater)

     def file_upload(self, local, remote, sudo=None, scp=False):
          """Uploads the local file to the remote path only if the remote path does not
        exists or the content are different."""
          return self._file.file_upload(self, local, remote, sudo, scp)

     def file_write(self, path: str, content: bytes, mode=None, owner=None, group=None, sudo=None, check=True, scp=False):
          """Writes the given content to the file at the given remote
        path, optionally setting mode/owner/group."""
          return self._file.file_write(self, path, content, mode, owner, group, sudo, check, scp)

# EOF
