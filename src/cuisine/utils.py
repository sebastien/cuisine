from pathlib import Path
import os
import datetime
import re


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


def shell_safe(path: str) -> str:
    """Makes sure that the given path/string is escaped and safe for shell"""
    return "".join([("\\" + _) if _ in " '\";`|" else _ for _ in path])


def single_quote_safe(line: str) -> str:
    """Returns a single-quoted version of the given line."""
    # FROM: https://stackoverflow.com/questions/1250079/how-to-escape-single-quotes-within-single-quoted-strings#1250279
    return line.replace("'", "'\"'\"'")


def normalize_path(path: str) -> Path:
    """Normalizes the given path, expanding variables and user home."""
    return Path(os.path.normpath(os.path.expanduser(os.path.expandvars(path))))


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
    return "%04d%02d%02d%02d%02d%02d" % (
        n.year, n.month, n.day, n.hour, n.minute, n.second
    )
# EOF
