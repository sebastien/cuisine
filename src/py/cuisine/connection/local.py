import subprocess
import threading
import shutil
import os
from pathlib import Path
from ..connection import Connection, CommandOutput
from typing import List, Tuple, Callable, Optional


class LocalConnection(Connection):

    TYPE = "local"

    def _connect(self):
        # TODO: We should detect if we need to switch user or not.
        pass

    def _disconnect(self):
        pass

    def _run(self, command: str) -> Optional[CommandOutput]:
        cmd = self.cd_prefix + command if self.cd_prefix else command
        return CommandOutput(
            run_local_raw(cmd, on_out=self.log.out, on_err=self.log.err)
        )

    def _upload(self, remote: str, source: Path):
        try:
            shutil.copy2(source, remote)
        except Exception as e:
            self.log.error(f"Cannot copy {source} to {remote}: {e}")

    def _cd(self, path: str):
        try:
            os.chdir(path)
        except FileNotFoundError as e:
            self.log.error(f"Path does not exist: {path}")


def run_local_raw(
    command: str,
    cwd=".",
    encoding="utf8",
    shell=True,
    on_out: Optional[Callable[[bytes], None]] = None,
    on_err: Optional[Callable[[bytes], None]] = None,
) -> Tuple[str, int, bytes, bytes]:
    """Low-level command running function. This spawns a new subprocess with
    two reader threads (stdout and stderr). It's fairly heavyweight but it's OK,
    Cuisine is about automation, not high-performance."""
    process = subprocess.Popen(
        command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
    )
    # NOTE: This is not ideal, but works well.
    # See http://stackoverflow.com/questions/15654163/how-to-capture-streaming-output-in-python-from-subprocess-communicate
    # At some point, we should use a single thread.
    out: List[bytes] = []
    err: List[bytes] = []

    def reader(channel, output, handler):
        # FIXME: This does not seem to stream, should develop a test case for that
        for line in channel:
            line = line or b""
            if line and handler:
                handler(line)
            output.append(line)

    t0 = threading.Thread(target=lambda: reader(process.stdout, out, on_out))
    t1 = threading.Thread(target=lambda: reader(process.stderr, err, on_err))
    t0.start()
    t1.start()
    try:
        process.wait()
    except KeyboardInterrupt as e:
        pass
    t0.join()
    t1.join()
    # We return the result
    return (command, process.returncode, b"".join(out), b"".join(err))


# EOF
