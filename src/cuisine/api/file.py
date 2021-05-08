import os.path
import base64
import tempfile
from ..api import APIModule as API
from ..decorators import logged, expose, requires
from ..utils import shell_safe


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
    def file_read(self, path, default=None):
        """Reads the *remote* file at the given path, if default is not `None`,
        default will be returned if the file does not exist."""
        # NOTE: We use base64 here to be sure to preserve the encoding (UNIX/DOC/MAC) of EOLs
        if default is None:
            assert self.file_exists(
                path), "cuisine.file_read: file does not exists {0}".format(path)
        elif not self.file_exists(path):
            return default
        frame = self.file_base64(path)
        return base64.b64decode(frame)

    @expose
    def file_exists(self, path: str) -> bool:
        """Tests if there is a *remote* file at the given path."""
        return self.api.run(f"test -e '{shell_safe(path)}' && echo OK ; true").value.endswith("OK")

    @expose
    def file_is_file(self, path):
        return self.api.run("test -f %s && echo OK ; true" % (shell_safe(path))).value.endswith("OK")

    @expose
    def file_is_dir(self, path: str) -> bool:
        return self.api.run("test -d %s && echo OK ; true" % (shell_safe(path))).value.endswith("OK")

    @expose
    def file_is_link(self, path: str) -> bool:
        return self.api.run("test -L %s && echo OK ; true" % (shell_safe(path))).value.endswith("OK")

    @logged
    def file_attribs(self, path, mode=None, owner=None, group=None):
        """Updates the mode/owner/group for the remote file at the given
        path."""
        return self.api.dir_attribs(path, mode, owner, group, False)

    @expose
    @logged
    @requires("stat")
    def file_attribs_get(self, path):
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
    def file_write(self, path: str, content: bytes, mode=None, owner=None, group=None, sudo=None, check=True, scp=False):
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
                    run("cp '%s' '%s'" %
                        (shell_safe(local_path), shell_safe(path)))
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
            self.file_attribs(path, mode=mode, owner=owner, group=group)

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

    @expose
    @logged
    def file_upload(self, local, remote, sudo=None, scp=False):
        """Uploads the local file to the remote path only if the remote path does not
        exists or the content are different."""
        # FIXME: Big files are never transferred properly!
        # XXX: this 'sudo' kw arg shadows the function named 'sudo'
        use_sudo = self.is_sudo() or sudo
        with open(local, "rb") as f:
            content = f.read()
        sig = hashlib.md5(content).hexdigest()
        if not self.file_exists(remote) or sig != self.file_md5(remote):
            if self.is_local():
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
                    self.connection().upload(remote, local)

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
        file_write(path, new_content)
        return True

    @expose
    @logged
    def file_append(self, path, content, mode=None, owner=None, group=None):
        """Appends the given content to the remote file at the given
        path, optionally updating its mode/owner/group."""
        # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
        self.run('echo "%s" | openssl base64 -A -d >> %s' %
                 (base64.b64encode(content), shell_safe(path)))
        self.file_attribs(path, mode, owner, group)

    @expose
    @logged
    @requires(("unlink"))
    def file_unlink(self, path: str):
        if self.file_exists(path):
            self.run("unlink %s" % (shell_safe(path)))

    @expose
    @logged
    def file_link(self, source, destination, symbolic=True, mode=None, owner=None, group=None):
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

    @expose
    @logged
    def file_base64(self, path: str):
        """Returns the base64-encoded content of the file at the given path."""
        if env_get(OPTION_HASH) == "python":
            return run("cat {0} | python -c 'import sys,base64;sys.stdout.write(base64.b64encode(sys.stdin.read()))'".format(shell_safe((path))))
        else:
            return run("cat {0} | openssl base64".format(shell_safe((path))))

    @logged
    def file_sha256(self, path: str):
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

    @expose
    @logged
    @requires("cat", "python", "openssl")
    def file_md5(self, path: str):
        """Returns the MD5 sum (as a hex string) for the remote file at the given path."""
        # NOTE: In some cases, sudo can output errors in here -- but the errors will
        # appear before the result, so we simply split and get the last line to
        # be on the safe side.
        # FIXME: This should go through the options
        if self.api.env_get(OPTION_HASH) == "python":
            if not _hashlib_supported():
                raise EnvironmentError(
                    "Remote host has not hashlib support. Please, use select_hash('openssl')")
            if self.file_exists(path):
                return self.api.run("cat {0} | python -c 'import sys,hashlib;sys.stdout.write(hashlib.md5(sys.stdin.read()).hexdigest())'".format(shell_safe((path))))
            else:
                return None
        else:
            if self.file_exists(path):
                return self.api.run('openssl dgst -md5 %s' % (shell_safe(path))).split("\n")[-1].split(")= ", 1)[-1].strip()
            else:
                return None
# EOF
