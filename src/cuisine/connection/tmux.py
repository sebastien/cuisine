from ..utils import single_quote_safe, timenum
from typing import Optional, List, Tuple
from pathlib import Path
import time
import re

from ..connection import Connection, CommandOutput


# SEE: https://gist.github.com/henrik/1967800
RE_TMUX_FIELDS = re.compile(r"\[[^\]]+\]|\([^\)]+\)|[^ ]+")


class TmuxConnection(Connection):

    def __init__(self, connection: Connection, session: str, window: int = 0):
        super().__init__()
        self._connection = connection
        self.session: str = session
        self.window: int = window
        self.tmux = Tmux(connection)

    def prompt(self):
        return f"{self._connection.prompt()}[tmux:{self.session}:{self.window}]"

    def _connect(self):
        if not self._connection.is_connected:
            self._connection._connect()

    def _disconnect(self):
        # We don't need to do anything specific there.
        pass

    def _run(self, command: str) -> Optional[CommandOutput]:
        cmd = self.cd_prefix + command
        success, out = self.tmux.run(self.session, self.window, cmd)
        return CommandOutput((command, 0 if success else 1, bytes(out or "", "utf8"), b""))

    def _upload(self, remote: str, source: Path):
        return self._connection._upload(remote, source)

    def _cd(self, path: str):
        self.tmux.run(self.session, self.window,
                      f"cd '{single_quote_safe(path)}'")


# TODO: We might want to change that so that an instance is not required, and
# we just have flat class methods.
class Tmux:
    """A simple wrapper around the `tmux`  terminal multiplexer that allows to
    create sessions and windows and execute arbitrary code in it.
    This is particularly useful if you want to run command on remote servers
    but still want easy access to their detailed output/interact with them."""

    def __init__(self, connection: Connection):
        """The Tmux wrapper takes a regular connection"""
        self.connection = connection

    def command(self, command: str, silent=True) -> str:
        """Executes the given Tmux command, given directly to the connection
        as arguments to `tmux …`."""
        cmd = f"tmux {command}"
        if silent:
            self.connection.log.push(None)
        res = self.connection.run(cmd)
        if silent:
            self.connection.log.pop()
        if res.is_success:
            return str(res.out_nocolor)
        else:
            self.connection.log.error(
                f"Could not run Tmux command '{command}' through connection '{self.connection.prompt()}'")
            return ""

    def session_list(self) -> List[str]:
        """Returns the list of sessions"""
        sessions = self.command("list-session").split("\n")
        return [_.split(":", 1)[0] for _ in sessions if _]

    def session_ensure(self, session: str) -> bool:
        """Ensures that the given session exists."""
        sessions = self.session_list()
        if session not in sessions:
            self.command(f"new-session -d -s {session}")
            return False
        else:
            return True

    def session_has(self, session: str) -> bool:
        """Tells if the given session exists or not."""
        return session in self.session_list()

    def window_list(self, session: str) -> List[int]:
        """Retuns the list of windows in the given session"""
        if not self.session_has(session):
            return []
        windows = filter(lambda _: _, self.command(
            f"list-windows -t {session}").split("\n"))
        res = []
        # OUTPUT is like:
        # 1: ONE- (1 panes) [122x45] [layout bffe,122x45,0,0,1] @1
        # 2: ONE* (1 panes) [122x45] [layout bfff,122x45,0,0,2] @2 (active)
        # 2: service@ip-172-31-15-180:~/dist* (1 panes) [80x23] [layout ae5f,80x23,0,0,2] @2 (active)
        for line in windows:
            fields = [_.group() for _ in RE_TMUX_FIELDS.finditer(line)]
            if len(fields) >= 2:
                index = int(fields[0][:-1])
                # TODO: If we want, we could use the name
                # name = (fields[1][:-1] if fields[1][-1]
                #         in "*-" else fields[1]).split("@", 1)[0].split(":", 1)[0]
            res.append(index)
        return res

    def window_get(self, session: str, window: int) -> List[str]:
        if not self.session_has(session):
            return []
        return window in self.window_list(session)

    def window_has(self, session: str, window: int) -> bool:
        return bool(self.window_get(session, window)) if self.session_has(session) else False

    def window_ensure(self, session: str, window: int) -> bool:
        self.session_ensure(session)
        if not self.window_get(session, window):
            self.command(
                f"set-option -g allow-rename off \\; new-window -t {session} -n {window} \\; set-window -g automatic-rename off ")

            return False
        else:
            return True

    def session_kill(self, session: str) -> bool:
        if not self.session_has(session):
            return False
        res = False
        for window in self.window_list(session):
            self.window_kill(session, window)
            res = True
        return res

    def window_kill(self, session: str, window: int) -> bool:
        if not self.session_has(session):
            return False
        res = False
        for window in self.window_get(session, window):
            self.command(f"kill-window -t {session}:{i}")
            res = True
        return res

    def read(self, session: str, window: int) -> str:
        """Reads from the given session and window"""
        return self.command(f"capture-pane -t {session}:{window} \\; save-buffer -", silent=True)

    def write(self, session: str, window: int, commands: str):
        self.command(
            f"send-keys -t {session}:{window}  '{single_quote_safe(commands)}'")
        self.command(f"send-keys -t {session}:{window} C-m")

    def halt(self, session: str, window: int):
        """Sends a `Ctrl-c` keystroke in this session."""
        self.command(f"send-keys -t {session}:{window} C-c")

    def run(self, session: str, window: int, command: str, timeout=2, resolution=0.1) -> Tuple[bool, str]:
        """This function allows to run a command and retrieve its output
        as given by the shell. It is quite error prone, as it will include
        your prompt styling and will only poll the output at `resolution` seconds
        interval."""
        self.window_ensure(session, window)
        delimiter = f"CMD_{timenum()}"
        output = None
        found = False
        start_delimiter = f"START_{delimiter}"
        ok_delimiter = f"OK_{delimiter}"
        end_delimiter = f"END_{delimiter}"
        # NOTE: First, we're wrapping the expression in a new shell context, and
        # we're also adding an OK delimiter to make sure we determine if the
        # command succeeded or not.
        tmux_command = f"echo {start_delimiter};({command}) && echo {ok_delimiter}; echo {end_delimiter};"
        self.write(session, window, tmux_command)
        # TODO: This should be a new thread
        result: list[str] = []
        is_success = False
        has_finished = False
        for _ in range(int(timeout / resolution)):
            # FIXME: We should find a better way to capture TMux's output. Either
            # we're detecting the new lines (starting from the bottom) and adding
            # them, or we find some other way to do that.
            output = self.read(session, window)
            has_data = False
            block = []
            for i, line in enumerate(output.split("\n")):
                if line.startswith(start_delimiter):
                    has_data = True
                elif line.startswith(ok_delimiter):
                    is_success = True
                    has_finished = True
                    break
                elif line.startswith(end_delimiter):
                    has_finished = True
                    break
                elif has_data:
                    block.append(line)
                    result = block
            if not has_finished:
                time.sleep(resolution)
        # The command output will be conveniently placed after the `echo
        # CMD_XXX` and before the output `CMD_XXX`. We use negative indexes
        # to avoid access problems when the program's output is too long.
        return is_success, "\n".join(result)
        # return output.rsplit(delimiter, 2)[-2].split("\n", 1)[-1] if found else None

    def is_responsive(self, session: str, window: int, timeout: int = 1, resolution: float = 0.1) -> Optional[bool]:
        """Tells if the given session/window is responsive, returning None if the session does not
        exist."""
        if self.session_has(session) and self.window_has(session, window):
            # Is the terminal responsive?
            key = f"TMUX_ACTION_CHECK_{timenum()}"
            self.write(session, window, "echo " + key)
            key = "\n" + key
            for _ in range(int(timeout / resolution)):
                text = self.read(session, window)
                is_responsive = text.find(key) != -1
                if not is_responsive:
                    time.sleep(resolution)
                else:
                    return True
            return False
        else:
            return None

# EOF
