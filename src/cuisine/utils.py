from pathlib import Path
import os

def shell_safe(path:str) -> str:
    """Makes sure that the given path/string is escaped and safe for shell"""
    return "".join([("\\" + _) if _ in " '\";`|" else _ for _ in path])

def quote_safe(line:str) -> str:
    """Makes sure that the single quotes are escaped"""
    return line.replace("'", "\\'")

def normalize_path( path:str ) -> Path:
    """Normalizes the given path, expanding variables and user home."""
    return Path(os.path.normpath(os.path.expanduser(os.path.expandvars(path))))

# EOF
