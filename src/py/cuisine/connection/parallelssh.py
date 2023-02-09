from ..connection import Connection, CommandOutput
from typing import Optional
import logging


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
            out = self.context.run_command(command)
            return CommandOutput.Make(
                command=command, out=out.stdout, err=out.stderr, status=out.exit_code
            )


# EOF
