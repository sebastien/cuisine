from ..connection import Connection, CommandOutput
from pathlib import Path
from typing import Optional

# SEE: https://gist.github.com/mlafeldt/841944


class ParamikoConnection(Connection):
    """Manages a remote connection through Paramiko.
     See <https://docs.paramiko.org>"""

    TYPE = "paramiko"

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, user: Optional[str] = None, password: Optional[str] = None, key: Optional[Path] = None):
        super().__init__(user=user, host=host, port=port, password=password, key=key)
        # SEE: https://docs.paramiko.org/en/stable/api/client.html
        try:
            import paramiko
            import paramiko.ssh_exception as paramiko_exceptions
        except ImportError as e:
            self.log.error(
                "Paramiko <https://docs.paramiko.org> is required: python -m pip install --user paramiko")
            raise e
        self.paramiko = paramiko
        self.paramiko_exceptions = paramiko_exceptions
        self._sftp = None
        self._context = None

    @property
    def sftp(self):
        if not self._sftp:
            if not self._context:
                self.log.error(f"Cannot create SFTP client, connection failed")
                return self._sftp
            self._sftp = self._context.open_sftp()
        return self._sftp

    def _connect(self) -> 'ParamikoConnection':
        # SEE: https://docs.paramiko.org/en/stable/api/client.html
        self._context = client = self.paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(self.paramiko.WarningPolicy)
        try:
            kwargs = dict((k, v) for k, v in dict(
                hostname=self.host,
                username=self.user,
                port=self.port,
                key_filename=str(self.key) if self.key else None,
                look_for_keys=True,
                timeout=5,
            ).items() if v is not None)
            client.connect(**kwargs)
        except self.paramiko_exceptions.AuthenticationException as e:
            self.log.error(
                f"Cannot connect to {self.user}@{self.host}:{self.port} using {self.type}: {e}")
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
            cmd = self.cd_prefix + command
            _, stdout, stderr = self._context.exec_command(cmd)
            # FIXME: We might be deadlocking here, we might want to reuse the
            # threaded readers.
            err = stderr.read()
            out = stdout.read()
            status = stdout.channel.recv_exit_status()
            return CommandOutput((command, status, out, err))

    def _upload(self, remote: str, local: Path):
        self.sftp.put(local, remote)

    def _write(self, remote: str, content: bytes) -> bool:
        with self.sftp.open(remote, "wb") as f:
            f.write(content)

    def _cd(self, path: str):
        sftp = self.sftp
        if sftp:
            self.sftp.chdir(path)
        else:
            raise RuntimeError("Unable to change directory")

    def disconnect(self) -> bool:
        if super().disconnect():
            if self._sftp:
                self._sftp.close()
                self._sftp = None
            self._context.close()
            self._context = None
            return True
        else:
            return False

# EOF
