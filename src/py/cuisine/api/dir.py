from ..api import APIModule
from ..decorators import logged, expose, requires
from ..utils import shell_safe, quoted
import os
from typing import Optional


class DirAPI(APIModule):

    @expose
    @logged
    @requires(("chmod", "chgrp", "chown"))
    def dir_attribs(self, path: str, mode=None, owner=None, group=None, recursive=False):
        """Updates the mode/owner/group for the given remote directory."""
        recursive = recursive and "-R " or ""
        if mode:
            self.api.run(f"chmod {recursive} '{mode}' {quoted(path)}")
        if owner:
            self.api.run(f"chown {recursive} '{owner}' {quoted(path)}")
        if group:
            self.api.run(f"chgrp {recursive} '{group}' {quoted(path)}")

    @expose
    @requires("test")
    def dir_exists(self, path: str) -> bool:
        """Tells if there is a remote directory at the given path."""
        return self.api.run(f"test -d {quoted(path)} && echo OK").is_ok

    @expose
    @logged
    @requires("rm")
    def dir_remove(self, path: str, recursive=True) -> Optional[bool]:
        """ Removes a directory """
        flag = "r" if recursive else ""
        if self.api.dir_exists(path):
            return self.api.run(f"rm -{flag}f {quoted(path)} && echo OK").is_ok
        else:
            return None

    @expose
    def dir_ensure_parent(self, path: str, recursive=True, mode=None, owner=None, group=None):
        """Ensures that the parent directory of the given path exists"""
        self.api.dir_ensure(os.path.dirname(
            path), recursive=recursive, mode=mode, owner=owner, group=group)
        return path

    @expose
    @requires(("mkdir"))
    def dir_ensure(self, path: str, recursive=True, mode=None, owner=None, group=None) -> str:
        """Ensures that there is a remote directory at the given path,
        optionally updating its mode/owner/group.

        If we are not updating the owner/group then this can be done as a single
        ssh call, so use that method, otherwise set owner/group after creation."""
        if not self.dir_exists(path):
            if not self.api.run(f"mkdir {'-p' if recursive else ''} {quoted(path)}").is_success:

                raise RuntimeError(
                    f"Could not create remote directory at: {path}")
        if owner or group or mode:
            self.api.dir_attribs(path, owner=owner, group=group,
                                 mode=mode, recursive=recursive)
        return path

# EOF
