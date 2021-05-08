from ..connection import Connection

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
