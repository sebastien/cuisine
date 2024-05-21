from ..connection import Connection, CommandOutput
from typing import Optional, Generator, Any
import logging

try:
    from pssh.output import HostOutput
except ImportError:
    HostOutput = Any


# TODO: We'll need to wrap the command output and find a way to manage
# iterators/streams.
class ParallelSSHCommandOutput(CommandOutput):
    def __init__(self, command: str, out: HostOutput):
        super().__init__((command, -1, b"", b""))
        self.psshOut: HostOutput = out


# NOTE: I can't get PSSH to work with keyfiles...
class ParallelSSHConnection(Connection):

    TYPE = "parallelssh"

    def init(self):
        try:
            from pssh.clients import SSHClient
            from pssh.exceptions import AuthenticationError
        except ImportError as e:
            logging.error(
                "parallel-ssh is required: run 'python -m pip install --user parallel-ssh' or pick another transport: {transport_options}"
            )
            raise e
        self.SSHClient = SSHClient
        self.AuthenticationError = AuthenticationError
        self.context: Optional[SSHClient] = None

    def _connect(self) -> "ParallelSSHConnection":
        try:
            client = self.SSHClient(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                pkey=self.key,
            )
        except self.AuthenticationError as e:
            logging.error(f"Cannot connect to {self.user}@{self.host}:{self.port}: {e}")
            raise e
        self.context = client
        return self

    def _run(self, command: str) -> CommandOutput:
        if not self.context:
            logging.error(f"Connection failed, cannot run: {command}")
            return CommandOutput.Make(command=command, status=127, out=b"", err=b"")
        else:
            # TODO: Parallel SSH outputs UTF8 and also uses generators
            # for stdout/stderr
            output = self.context.run_command(command)
            for host, stream in output.items():
                print(host, stream)
            # return CommandOutput.Make(
            #     command=command, out=out.stdout, err=out.stderr, status=out.exit_code
            # )

    def _disconnect(self):
        if self.context:
            self.context.disconnect()
            self.context = None


# EOF
