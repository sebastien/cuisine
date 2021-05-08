from ..connections import Connection

class ParallelSSHConnection(Connection):

    TYPE = "parallel-ssh"

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[str]=None ):
        super().__init__(user,password,key)

    def init( self ):
        try:
            from pssh.clients import SSHClient
            from pssh.exceptions import AuthenticationError
        except ImportError as e:
            logging.error("parallel-ssh is required: run 'ppython -m pip install --user parallel-ssh' or pick another transport: {transport_options}")
            raise e
        self.SSHClient = SSHClient
        self.AuthenticationError = AuthenticationError
        self.context:Optional[SSHClient] = None

    def connect( self, host:str, port=22 ) -> 'ParallelSSHConnection':
        super().connect(host, port)
        try:
            client = self.SSHClient(host)
        except self.AuthenticationError as e:
            logging.error(f"Cannot connect to f{host}: {e}")
            raise e
        self.context = client
        return self

    def run( self, command ) -> CommandOutput:
        super().run(command)
        out = client.run_command(command)
        return CommandOutput(out=out.stdout, err=out.stdeer, status=out.exist_code)


