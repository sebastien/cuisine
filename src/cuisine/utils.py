from pathlib import Path
from typing import Union
from typing import Dict, List
import os
import datetime
import re
import random


# --
# # Utilities
#
# This module contains functions that make it easier to work with shell data, mainly
# around quoting, escaping and normalizing.

# FROM: https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
# 7-bit and 8-bit C1 ANSI sequences
RE_ANSI_ESCAPE_8BIT = re.compile(
    br'(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])'
)

RE_ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def strip_ansi_bytes(data: bytes) -> bytes:
    return RE_ANSI_ESCAPE_8BIT.sub(b'', data)


def strip_ansi(data: str) -> str:
    return RE_ANSI_ESCAPE.sub('', data)


def shell_safe(path: Union[Path, str]) -> str:
    """Makes sure that the given path/string is escaped and safe for shell"""
    return "".join([("\\" + _) if _ in " '\";`|" else _ for _ in str(path)])


def single_quote_safe(line: str) -> str:
    """Returns a single-quoted version of the given line."""
    # FROM: https://stackoverflow.com/questions/1250079/how-to-escape-single-quotes-within-single-quoted-strings#1250279
    return line.replace("'", "'\"'\"'")


def quoted(line: str) -> str:
    return f"'{single_quote_safe(line)}'"


def normalize_path(path: str) -> Path:
    """Normalizes the given path, expanding variables and user home."""
    return Path(os.path.normpath(os.path.expanduser(os.path.expandvars(path))))


def make_options_str(options: Dict[str, Union[None, str, int, bool]]) -> str:
    """Like `make_options`, but returning a string"""
    return " ".join(make_options(options)) or ""


def make_options(options: Dict[str, Union[None, str, int, bool]]) -> List[str]:
    """Converts a dict of options to a string."""
    res: List[str] = []
    for k, v in options.items():
        if v in (None, False):
            continue
        if v is True:
            res.append(k)
        else:
            res.append(f"{k}{quoted(v)}")
    return res


def prefix_command(command: str, prefix: str) -> str:
    if not command.startswith(prefix):
        return f"{prefix} {command}"
    else:
        return command


def timestamp():
    """Returns the current timestamp as an ISO-8601 time
    ("1977-04-22T01:00:00-05:00")"""
    n = datetime.datetime.now()
    return "%04d-%02d-%02dT%02d:%02d:%02d" % (
        n.year, n.month, n.day, n.hour, n.minute, n.second
    )


def timenum():
    """Like timestamp, but just the numbers."""
    n = datetime.datetime.now()
    return "%04d%02d%02d%02d%02d%02d%02d" % (
        n.year, n.month, n.day, n.hour, n.minute, n.second, random.randint(
            0, 99)
    )


def ssh_remove_known_host(ips: Union[str, List[str]]) -> bool:
    known_hosts = Path("~/.ssh/known_hosts").expanduser()
    all_ips = [ips] if isinstance(ips, str) else ips
    if known_hosts.exists():
        with open(known_hosts) as f:
            lines = list(f.readlines())
        filtered = [_ for _ in lines if _.split()[0] not in all_ips]
        if len(lines) != len(filtered):
            with open(known_hosts, "wt") as f:
                f.write("".join(filtered))
            return True
    return False


# EOF
