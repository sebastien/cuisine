import os.path
import base64
import tempfile
import hashlib
import os
from ..api import APIModule as API
from ..decorators import logged, expose, requires
from ..utils import shell_safe, quoted
from typing import Dict, Union, Optional


class FileAPI(API):

    @expose
    def file_name(self, path: str) -> str:
        """Returns the file name for the given path."""
        return os.path.basename(path)

    @expose
    @logged
    @requires("cp")
    def file_backup(self, path: str, suffix=".orig", once=False):
        """Backups the file at the given path in the same directory, appending
        the given suffix. If `once` is True, then the backup will be skipped if
        there is already a backup file."""
        backup_path = path + suffix
        if once and self.file_exists(backup_path):
            return False
        else:
            return self.api.run("cp -a {0} {1}".format(
                shell_safe(path),
                shell_safe(backup_path)
            ))

    @expose
    @logged
    def file_read(self, path: str) -> bytes:
        """Reads the *remote* file at the given path, if default is not `None`,
        default will be returned if the file does not exist."""
        # NOTE: We use base64 here to be sure to preserve the encoding (UNIX/DOC/MAC) of EOLs
        if not self.file_exists(path):
            return b""
        else:
            data = self.file_base64(path)
            if not data:
                return b""
            else:
                return base64.b64decode(data)

    @expose
    @logged
    def file_read_str(self, path: str) -> str:
        try:
            return str(self.api.file_read(path), "utf8")
        except UnicodeDecodeError as e:
            raise RuntimeError(f"Cannot decode contents of file '{path}': {e}")

    @expose
    def file_exists(self, path: str) -> bool:
        """Tests if there is a *remote* file at the given path."""
        return self.api.run(f"test -e {quoted(path)} && echo OK").is_ok

    @expose
    def file_is_file(self, path: str):
        """Tells if the given path is a file or not"""
        return self.api.run(f"test -f '{shell_safe(path)}' && echo OK; true").is_ok

    @expose
    def file_is_dir(self, path: str) -> bool:
        """Tells if the given path is a directory or not"""
        return self.api.run(f"test -d '{shell_safe(path)}' && echo OK ; true").is_ok

    @expose
    def file_is_link(self, path: str) -> bool:
        """Tells if the given path is a symlink or not"""
        return self.api.run(f"test -L '{shell_safe(path)}' && echo OK ; true").is_ok

    @logged
    @expose
    def file_attribs(self, path: str, mode=None, owner=None, group=None):
        """Updates the mode/owner/group for the remote file at the given
        path."""
        return self.api.dir_attribs(path, mode, owner, group, False)

    @expose
    @logged
    @requires("stat")
    def file_attribs_get(self, path: str) -> Dict[str, str]:
        """Return mode, owner, and group for remote path.
        Return mode, owner, and group if remote path exists, 'None'
        otherwise.
        """
        if self.file_exists(self, path):
            fs_check = run('stat %s %s' %
                           (shell_safe(path), '--format="%a %U %G"'))
            (mode, owner, group) = fs_check.split(' ')
            return {'mode': mode, 'owner': owner, 'group': group}
        else:
            return None

    @expose
    @logged
    def file_write(self, path: str, content: Union[str, bytes], mode=None, owner=None, group=None, sudo=None, check=True, scp=False):
        """Writes the given content to the file at the given remote
        path, optionally setting mode/owner/group."""
        # FIXME: Big files are never transferred properly!
        # Gets the content signature and write it to a secure tempfile
        bytes_content = content if isinstance(
            content, bytes) else bytes(content, "utf8")
        self.api.dir_ensure(os.path.dirname(path))
        sig = hashlib.md5(bytes_content).hexdigest()
        fd, local_path = tempfile.mkstemp()
        os.write(fd, bytes_content)
        # Upload the content if necessary
        remote_sig = self.file_md5(path)
        if sig != remote_sig:
            self.api.connection().write(path, bytes_content)
        # Remove the local temp file
        os.fsync(fd)
        os.close(fd)
        os.unlink(local_path)
        # Ensures that the signature matches
        if check:
            file_sig = self.file_md5(path)
            assert sig == file_sig, f"File content does not matches file: {path}, got {file_sig}, expects {sig}"
        return self.file_attribs(path, mode=mode, owner=owner, group=group)

    @expose
    @logged
    def file_ensure(self, path, mode=None, owner=None, group=None, scp=False):
        """Updates the mode/owner/group for the remote file at the given
        path."""
        if self.file_exists(path):
            self.file_attribs(path, mode=mode, owner=owner, group=group)
        else:
            self.file_write(path, "", mode=mode, owner=owner,
                            group=group, scp=scp)

    def file_is_same(self, local: str, remote: str) -> bool:
        """Tells if the local and remote file have the same content. Both
        file must exist and have the same signature."""
        if not os.path.exists(local):
            return False
        if not self.api.file_exits(remote):
            return False
        with open(local, "rb") as f:
            content = f.read()
        return self.file_md5(remote) == hashlib.md5(content).hexdigest()

    @expose
    @logged
    def file_upload(self, local: str, remote: str):
        """Uploads the local file to the remote path only if the remote path does not
        exists or the content are different."""
        # FIXME: Big files are never transferred properly!
        assert os.path.exists(
            local), f"Cannot upload, local file does not exists: {local}"
        self.api.dir_ensure(os.path.dirname(remote))
        self.api.connection().upload(remote, local)

    @expose
    @logged
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
        assert self.file_exists(path), "File does not exists: " + path
        old_content = self.file_read(path)
        new_content = updater(old_content) if updater else old_content
        if (old_content == new_content):
            return False
        # assert type(new_content) in (str, unicode, fabric.operations._AttributeString), "Updater must be like (string)->string, got: %s() = %s" %  (updater, type(new_content))
        self.api.file_write(path, new_content)
        return True

    @expose
    @logged
    def file_append(self, path: str, content: Union[bytes, str], mode: Optional[str] = None, owner: Optional[str] = None, group: Optional[str] = None):
        """Appends the given content to the remote file at the given
        path, optionally updating its mode/owner/group."""
        # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
        # NOTE: We use tee to preserve the writing rights (sudo)
        content_bytes = content if isinstance(
            content, bytes) else bytes(content, "utf8")
        # SEE: https://unix.stackexchange.com/questions/503990/redirecting-from-right-to-left
        self.api.run(
            f"tee -a {quoted(path)} < <(echo {quoted(str(base64.b64encode(content_bytes), 'ascii'))} | openssl base64 -A -d) > /dev/null")
        return self.api.file_attribs(path, mode, owner, group)

    @expose
    @logged
    @requires(("unlink"))
    def file_unlink(self, path: str):
        """Removes the given file path if it exists"""
        if self.file_exists(path):
            self.api.run(f"unlink {shell_safe(path)}")

    @expose
    @logged
    def file_link(self, source, destination, symbolic=True, mode=None, owner=None, group=None):
        """Creates a (symbolic) link between source and destination on the remote host,
        optionally setting its mode/owner/group."""
        if self.file_exists(destination) and (not self.file_is_link(destination)):
            raise Exception(
                "Destination already exists and is not a link: %s" % (destination))
        # FIXME: Should resolve the link first before unlinking
        if self.file_is_link(destination):
            self.file_unlink(destination)
        if symbolic:
            self.api.run('ln -sf %s %s' %
                         (shell_safe(source), shell_safe(destination)))
        else:
            self.api.run('ln -f %s %s' %
                         (shell_safe(source), shell_safe(destination)))
        self.file_attribs(destination, mode, owner, group)

    # SHA256/MD5 sums with openssl are tricky to get working cross-platform
    # SEE: https://github.com/sebastien/cuisine/pull/184#issuecomment-102336443
    # SEE: http://stackoverflow.com/questions/22982673/is-there-any-function-to-get-the-md5sum-value-of-file-in-linux

    # NOTE: We need to use `cat` here as the first command will be run with sudo

    @expose
    @logged
    @requires("python", "openssl")
    def file_base64(self, path: str) -> str:
        """Returns the base64-encoded content of the file at the given path."""
        # TODO: Support options
        option_hash = self.api.config_get("hash", "openssl")
        if option_hash == "python":
            # FIXME: This does not seem to work al
            return self.api.run(f"cat {quoted(path)} | {self.api.command('python')} -c 'import sys,base64;sys.stdout.buffer.write(base64.b64encode(sys.stdin.buffer.read()))'").out
        else:
            return self.api.run(f"cat {quoted(path)} | {self.api.command('openssl')} base64").out

    @expose
    @logged
    def file_sha256(self, path: str):
        """Returns the SHA-256 sum (as a hex string) for the remote file at the given path."""
        # NOTE: In some cases, sudo can output errors in here -- but the errors will
        # appear before the result, so we simply split and get the last line to
        # be on the safe side.
        option_hash = self.api.config_get("hash", "python")
        if not self.file_exists(path):
            return None
        elif option_hash == "python":
            return self.api.run(f"cat {quoted(path)} | ${self.api.command('python')} -c 'import sys,hashlib;sys.stdout.buffer.write(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'")
        else:
            return self.api.run(f"openssl dgst -sha256 {quoted(path)}").split("\n")[-1].split(")= ", 1)[-1].strip()

    @expose
    @logged
    @requires("cat", "python", "openssl")
    def file_md5(self, path: str):
        """Returns the MD5 sum (as a hex string) for the remote file at the given path."""
        # NOTE: In some cases, sudo can output errors in here -- but the errors will
        # appear before the result, so we simply split and get the last line to
        # be on the safe side.
        # FIXME: This should go through the options
        option_hash = self.api.config_get("hash", "openssl")
        if not self.file_exists(path):
            return None
        elif option_hash == "python":
            return self.api.run(f"python -c 'import sys,hashlib;sys.stdout.buffer.write(hashlib.md5(sys.stdin.buffer.read()).hexdigest())' < {quoted(path)}").out
        else:
            return self.api.run(
                f"openssl dgst -md5 {quoted(path)}").checked_value.split(")= ", 1)[-1]
# EOF
