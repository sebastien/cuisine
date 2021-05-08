# =============================================================================
#
# CONNECTION
#
# =============================================================================

class Connection:
    """Abstract implementation of a remote SSH connection. Connections are
    created with credentials, and then we can connect to and disconnect from
    the connections. Commands can be run as strings, and return
    a `CommandOutput` object."""

    TYPE = "unknown"

    def __init__( self, user:Optional[str]=None, password:Optional[str]=None, key:Optional[Path]=None ):
        self.key =  Path(os.path.normpath(os.path.expanduser(os.path.expandvars(key)))) if key else None
        self.password:Optional[str] = password
        self.user:Optional[str] = user
        self.host:Optional[str] = "localhost"
        self.port = 22
        self.isConnected = False
        self.type = self.TYPE
        self._path:Optional[str] = None
        self.cd_prefix:str = ""
        self.init()

    @property
    def path( self ) -> Optional[str]:
        return self._path 

    @path.setter
    def path( self, value:str ):
        self._path = value
        # We store the cd_prefix as we need to prefix commands with
        # a directory.
        self.cd_prefix = f"cd '{shell_safe(value)}';"if value else ""

    def init( self ):
        pass

    def connect( self, host:str, port=None ) -> 'Connection':
        assert not self.isConnected, "Connection already made, call 'disconnect' first"
        self.host = host or self.host
        self.port = port or self.port
        return self

    def reconnect( self, user:Optional[str], host:Optional[str], port:Optional[int] ) -> 'Connection':
        self.disconnect()
        self.user = user or self.user
        host = host or self.host
        port = port or self.port
        return self.connect(host, port)

    def run( self, command:str ) -> Optional[CommandOutput]:
        logging.info(command)
        return None

    def cd( self, path:str ) -> bool:
        raise NotImplementedError

    def upload( self, remote:str, local:str ) -> bool:
        """Copies from the local file to the remote path"""
        local_path = Path(os.path.normpath(os.path.expanduser(os.path.expandvars(local))))
        if not local_path.exists():
            raise ValueError(f"Local path does not exists: '{local}'")
        return True

    def write( self, remote:str, content:bytes ) -> bool:
        """Writes the given content to the remote path"""
        return True

    def disconnect( self ) -> bool:
        return self.isConnected

