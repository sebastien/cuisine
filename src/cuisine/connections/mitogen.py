from ..connections import Connection

class MitogenConnection(Connection):
    """Manages a remote connection through Mitogen. 
     See <https://mitogen.networkgenomics.com/>."""

    TYPE = "mitogen"

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[Path]=None ):
        super().__init__(user,password,key)

    def init( self ):
        try:
            import mitogen
            import mitogen.utils as mitogen_utils
            import mitogen.master as mitogen_master
            import mitogen.ssh as mitogen_ssh
        except ImportError as e:
            logging.error("Mitogen <https://mitogen.networkgenomics.com/> is required: python -m pip install --user mitogen")
            raise e
        self.mitogen = mitogen
        self.mitogen_utils = mitogen_utils
        self.mitogen_master = mitogen_master
        self.mitogen_ssh = mitogen_ssh

    def connect( self, host:str, port=22 ) -> 'MitogenConnection':
        # NOTE: Connect will update self.{host,port}
        super().connect(host, port)
        broker = self.mitogen_master.Broker()
        router = self.mitogen_master.Router(broker)
        try:
            # NOTE: See <https://github.com/mitogen-hq/mitogen/blob/master/mitogen/ssh.py>
            self.context = router.ssh(hostname=self.host, username=self.user, port=self.port, identity_file=self.key)
        except self.mitogen_ssh.PasswordError as e:
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
            return CommandOutput(self.context.call(run_local_raw, command))


