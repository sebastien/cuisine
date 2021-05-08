
# =============================================================================
#
# RSYNC
#
# =============================================================================


def rsync(local_path: str, remote_path: str, compress: bool = True, progress: bool = False, verbose: bool = True, owner: bool = None, group: bool = None):
    """Rsyncs local to remote, using the connection's host and user."""
    options = "-a"
    if compress:
        options += "z"
    if verbose:
        options += "v"
    if progress:
        options += " --progress"
    if owner or group:
        assert owner and group or not owner
        options += " --chown={0}{1}".format(owner or "",
                                            ":" + group if group else "")
    with mode_local():
        run("rsync {options} {local} {user}@{host}:{remote}".format(
            options=options,
            host=host(),
            user=user(),
            local=local_path,
            remote=remote_path,
        ))
