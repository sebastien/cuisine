from ..connection import Connection, CommandOutput
from .. import logging
from .local import run_local_raw
from ..utils import quoted
from pathlib import Path
from typing import Optional
import tempfile
import threading
import os


def file_write(content: bytes):
    fd, path = tempfile.mkstemp()
    os.write(fd, content)
    os.close(fd)
    return path


class MitogenConnection(Connection):
    """Manages a remote connection through Mitogen.
     See <https://mitogen.networkgenomics.com/>."""

    TYPE = "mitogen"
    ACTIVE = 0

    # --
    # The mitogen *broker* and  *router* are shared across connections, and
    # will be recycled.

    BROKER = None
    ROUTER = None

    def init(self):
        try:
            import mitogen
            import mitogen.utils as mitogen_utils
            import mitogen.master as mitogen_master
            import mitogen.ssh as mitogen_ssh
        except (ImportError, ModuleNotFoundError) as e:
            logging.error(
                "Mitogen <https://mitogen.networkgenomics.com/> is required: python -m pip install --user mitogen")
            raise e
        self.mitogen = mitogen
        self.mitogen_utils = mitogen_utils
        self.mitogen_master = mitogen_master
        self.mitogen_ssh = mitogen_ssh

    def _connect(self) -> 'MitogenConnection':
        # NOTE: Connect will update self.{host,port}
        # NOTE: We reuse Brokers and Routers, and also cleans them up
        broker = MitogenConnection.BROKER = MitogenConnection.BROKER or self.mitogen_master.Broker()
        router = MitogenConnection.ROUTER = MitogenConnection.ROUTER or self.mitogen_master.Router(
            broker)
        try:
            # NOTE: See <https://github.com/mitogen-hq/mitogen/blob/master/mitogen/ssh.py>
            self.context = router.ssh(
                hostname=self.host,
                username=self.user,
                port=self.port,
                identity_file=self.key,
                connect_timeout=self.timeout,
            )
            MitogenConnection.ACTIVE += 1
        except self.mitogen_ssh.PasswordError as e:
            logging.fatal(
                f"Cannot connect to {self.user}@{self.host}:{self.port} using {self.type}: {e}")
            self.context = None
            self.is_connected = False
            return self
        return self

    def _write(self, path: str, content: bytes) -> CommandOutput:
        temp_path = self.context.call(file_write, content)
        command = f"touch {quoted(path)}; cp --attributes-only {quoted(temp_path)} {quoted(path)}; mv -f {quoted(temp_path)} {quoted(path)}"
        return self.run(command)

    def _cd(self, path: str):
        self.context.call(os.chdir, path)

    def _run(self, command) -> CommandOutput:
        if not self.context:
            logging.error(f"Connection failed, cannot run: {command}")
            return CommandOutput((command, 127, b"", b""))
        else:
            return CommandOutput(self.context.call(run_local_raw, command))

    def _disconnect(self):
        MitogenConnection.ACTIVE -= 1
        self.context.shutdown(wait=True)
        # We do a final shutdown when we don't have any active connection
        if not MitogenConnection.ACTIVE:
            MitogenConnection.BROKER.shutdown()
            MitogenConnection.ROUTER = None
            MitogenConnection.BROKER = None
        self.context = None

# EOF
