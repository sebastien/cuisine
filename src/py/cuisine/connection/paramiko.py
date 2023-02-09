from ..connection import Connection, CommandOutput
from ..utils import quoted
from pathlib import Path
from typing import Optional

# SEE: https://gist.github.com/mlafeldt/841944
# NOTE: Fedora still has a bug that prevents Paramiko to work https://bugzilla.redhat.com/show_bug.cgi?id=1775693


class ParamikoConnection(Connection):
    """Manages a remote connection through Paramiko.
    See <https://docs.paramiko.org>"""

    TYPE = "paramiko"

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        key: Optional[Path] = None,
    ):
        super().__init__(user=user, host=host, port=port, password=password, key=key)
        # SEE: https://docs.paramiko.org/en/stable/api/client.html
        try:
            import paramiko
            import paramiko.sftp_client
            import paramiko.ssh_exception as paramiko_exceptions
        except ImportError as e:
            self.log.error(
                "Paramiko <https://docs.paramiko.org> is required: python -m pip install --user paramiko"
            )
            raise e
        self.paramiko = paramiko
        self.paramiko_exceptions = paramiko_exceptions
        self._context: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.sftp_client.SFTPClient] = None

    @property
    def sftp(self):
        if not self._sftp:
            if not self._context:
                self.log.error("Cannot create SFTP client, connection failed")
                return self._sftp
            self._sftp = self._context.open_sftp()
        return self._sftp

    def _connect(self) -> "ParamikoConnection":
        # SEE: https://docs.paramiko.org/en/stable/api/client.html
        self._context = client = self.paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(self.paramiko.AutoAddPolicy())
        try:
            kwargs = dict(
                (k, v)
                for k, v in dict(
                    hostname=self.host,
                    username=self.user,
                    port=self.port,
                    key_filename=str(self.key) if self.key else None,
                    look_for_keys=True,
                    timeout=self.timeout,
                ).items()
                if v is not None
            )
            client.connect(**kwargs)
        except self.paramiko_exceptions.AuthenticationException as e:
            self.log.error(
                f"Cannot connect to {self.user}@{self.host}:{self.port} using {self.type}: {e}"
            )
            self._context = None
            self.is_connected = False
            raise e
            return self
        return self

    def _run(self, command: str) -> CommandOutput:
        if not self._context:
            self.log.error(f"Connection failed, cannot run: {command}")
            return CommandOutput((command, 127, b"", b""))
        else:
            cmd = f"{self.cd_prefix}{command}" if self.cd_prefix else command
            _, stdout, stderr = self._context.exec_command(cmd)
            # FIXME: We might be deadlocking here, we might want to reuse the
            # threaded readers.
            err = stderr.read()
            out = stdout.read()
            status = stdout.channel.recv_exit_status()
            return CommandOutput((command, status, out, err))

    def _upload(self, remote: str, local: Path):
        if self.sftp:
            self.sftp.put(str(local), remote)
        else:
            raise RuntimeError("Unabled to create SFTP client")

    def _download(self, remote: str, local: Path):
        if self.sftp:
            self.sftp.get(remote, str(local))
        else:
            raise RuntimeError("Unabled to create SFTP client")

    def _write(self, remote: str, content: bytes) -> bool:
        if self.sftp:
            with self.sftp.open(remote, "wb") as f:
                f.write(content)
                return True
        else:
            return False

    def _cd(self, path: str):
        success: bool = False
        if self._sftp:
            self._sftp.chdir(path)
            success = True
        if self._context:
            success = True
            # NOTE: There's no persistent CWD with Paramiko, so we need
            # to change the CWD for every command!
        return success

    def _disconnect(self) -> bool:
        connected: bool = False
        if self._sftp:
            self._sftp.close()
            self._sftp = None
            connected = True
        if self._context:
            self._context.close()
            self._context = None
            connected = True
        return connected


# EOF
