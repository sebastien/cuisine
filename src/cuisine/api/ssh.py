# =============================================================================
#
# SSH
#
# =============================================================================


def ssh_keygen(user, keytype="dsa"):
    """Generates a pair of ssh keys in the user's home .ssh directory."""
    d = user_check(user)
    assert d, "User does not exist: %s" % (user)
    home = d["home"]
    key_file = home + "/.ssh/id_%s.pub" % keytype
    if not file_exists(key_file):
        dir_ensure(home + "/.ssh", mode="0700", owner=user, group=user)
        run("ssh-keygen -q -t %s -f '%s/.ssh/id_%s' -N ''" %
            (keytype, home, keytype))
        file_attribs(home + "/.ssh/id_%s" % keytype, owner=user, group=user)
        file_attribs(home + "/.ssh/id_%s.pub" %
                     keytype, owner=user, group=user)
        return key_file
    else:
        return key_file


def ssh_authorize(user, key):
    """Adds the given key to the '.ssh/authorized_keys' for the given
    user."""
    d = self.api.user_get(user, need_passwd=False)
    group = d["gid"]
    keyf = d["home"] + "/.ssh/authorized_keys"
    if key[-1] != "\n":
        key += "\n"
    if file_exists(keyf):
        d = file_read(keyf)
        if file_read(keyf).find(key[:-1]) == -1:
            file_append(keyf, key)
            return False
        else:
            return True
    else:
        # Make sure that .ssh directory exists, see #42
        dir_ensure(os.path.dirname(keyf), owner=user, group=group, mode="700")
        file_write(keyf, key,             owner=user, group=group, mode="600")
        return False


def ssh_unauthorize(user, key):
    """Removes the given key to the remote '.ssh/authorized_keys' for the given
    user."""
    key = key.strip()
    d = user_check(user, need_passwd=False)
    group = d["gid"]
    keyf = d["home"] + "/.ssh/authorized_keys"
    if file_exists(keyf):
        file_write(keyf, "\n".join(_ for _ in file_read(keyf).split(
            "\n") if _.strip() != key), owner=user, group=group, mode="600")
        return True
    else:
        return False
