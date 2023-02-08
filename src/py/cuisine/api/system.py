# =============================================================================
#
# SYSTEM
#
# =============================================================================

def system_uuid_alias_add():
    """Adds system UUID alias to /etc/hosts.
    Some tools/processes rely/want the hostname as an alias in
    /etc/hosts e.g. `127.0.0.1 localhost <hostname>`.
    """
    with mode_sudo():
        old = "127.0.0.1 localhost"
        new = old + " " + system_uuid()
        file_update('/etc/hosts', lambda x: text_replace_line(x, old, new)[0])


def system_uuid():
    """Gets a machines UUID (Universally Unique Identifier)."""
    return sudo('dmidecode -s system-uuid | tr "[A-Z]" "[a-z]"')


