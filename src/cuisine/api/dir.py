from ..api import API
from ..decorators import logged, expose, requires
from ..utils import shell_safe


class DirAPI(API):

    @expose
    @logged
    @requires(("chmod", "chgrp", "chown"))
    def dir_attribs(self: API, path: str, mode=None, owner=None, group=None, recursive=False):
        """Updates the mode/owner/group for the given remote directory."""
        recursive = recursive and "-R " or ""
        safe_path = shell_safe(path)
        if mode:
            self.run(f"chmod {recursive} '{mode}' '{safe_path}'")
        if owner:
            self.run(f"chown {recursive} '{owner}' '{safe_path}'")
        if group:
            self.run(f"chgrp {recursive} '{group}' '{safe_path}'")

    @expose
    @requires("test")
    def dir_exists(self: API, path: str) -> bool:
        """Tells if there is a remote directory at the given path."""
        return self.run(f"test -d '{shell_safe(path)}' && echo OK ; true").value.endswith("OK")

    @expose
    @logged
    @requires("rm")
    def dir_remove(self: API, path: str, recursive=True):
        """ Removes a directory """
        flag = ''
        if recursive:
            flag = 'r'
        if self.dir_exists(path):
            return self.run('rm -%sf %s && echo OK ; true' % (flag, shell_safe(path)))

    @expose
    def dir_ensure_parent(self: API, path: str):
        """Ensures that the parent directory of the given path exists"""
        self.dir_ensure(os.path.dirname(path))
        return path

    @expose
    @requires(("mkdir"))
    def dir_ensure(self: API, path: str, recursive=True, mode=None, owner=None, group=None) -> str:
        """Ensures that there is a remote directory at the given path,
        optionally updating its mode/owner/group.

        If we are not updating the owner/group then this can be done as a single
        ssh call, so use that method, otherwise set owner/group after creation."""
        if not self.dir_exists(path):
            self.run(f"mkdir {'-p' if recursive else ''} '{shell_safe(path)}")
        if owner or group or mode:
            self.dir_attribs(path, owner=owner, group=group,
                             mode=mode, recursive=recursive)
        return path

# EOF
