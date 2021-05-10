from ..api import APIModule
from ..decorators import logged, expose, requires
from ..utils import shell_safe
import os


class DirAPI(APIModule):

    @expose
    @logged
    @requires(("chmod", "chgrp", "chown"))
    def dir_attribs(self, path: str, mode=None, owner=None, group=None, recursive=False):
        """Updates the mode/owner/group for the given remote directory."""
        recursive = recursive and "-R " or ""
        safe_path = shell_safe(path)
        if mode:
            self.api.run(f"chmod {recursive} '{mode}' '{safe_path}'")
        if owner:
            self.api.run(f"chown {recursive} '{owner}' '{safe_path}'")
        if group:
            self.api.run(f"chgrp {recursive} '{group}' '{safe_path}'")

    @expose
    @requires("test")
    def dir_exists(self, path: str) -> bool:
        """Tells if there is a remote directory at the given path."""
        return self.api.run(f"test -d '{shell_safe(path)}' && echo OK ; true").value.endswith("OK")

    @expose
    @logged
    @requires("rm")
    def dir_remove(self, path: str, recursive=True):
        """ Removes a directory """
        flag = "r" if recursive else ""
        if self.api.dir_exists(path):
            return self.api.run(f"rm -{flag}f '{shell_safe(path)}' && echo OK ; true")

    @expose
    def dir_ensure_parent(self, path: str):
        """Ensures that the parent directory of the given path exists"""
        self.api.dir_ensure(os.path.dirname(path))
        return path

    @expose
    @requires(("mkdir"))
    def dir_ensure(self, path: str, recursive=True, mode=None, owner=None, group=None) -> str:
        """Ensures that there is a remote directory at the given path,
        optionally updating its mode/owner/group.

        If we are not updating the owner/group then this can be done as a single
        ssh call, so use that method, otherwise set owner/group after creation."""
        if not self.dir_exists(path):
            self.api.run(
                f"mkdir {'-p' if recursive else ''} '{shell_safe(path)}'")
        if owner or group or mode:
            self.api.dir_attribs(path, owner=owner, group=group,
                                 mode=mode, recursive=recursive)
        return path

# EOF
