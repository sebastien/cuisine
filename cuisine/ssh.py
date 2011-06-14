# -*- coding: utf-8 -*-
"""
    cuisine.ssh
    ~~~~~~~~~~~

    Helper functions for working with remote SSH configuration
    files: ``~/.ssh/id_*``, ``~/.ssh/id_*.pub`` and
    ``~/.ssh/authorized_keys``.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

from . import user as _user, run, dir, file


def keygen(user, keytype="dsa"):
    """Generates a pair of SSH keys in the user's ``~/.ssh`` directory.

    :param unicode user: name of the user to generate key for.
    :param unicode keytype: see :man ssh-keygen(1): for details.
    :raises ValueError: when a given user doesn't exist.
    """
    home = _user.get(user)["home"]
    if not file.exists(home + "/.ssh/id_%s.pub" % keytype):
        dir.ensure(home + "/.ssh", mode="0700", owner=user, group=user)
        run("ssh-keygen -q -t %s -f '%s/.ssh/id_%s' -N ''" % (home, keytype, keytype))
        file.attrs(home + "/.ssh/id_%s" % keytype,     owner=user, group=user)
        file.attrs(home + "/.ssh/id_%s.pub" % keytype, owner=user, group=user)


def authorize(user, key):
    """Adds a given key to the user's ``~/.ssh/authorized_keys``.

    :param unicode user: name of the user to add a key for.
    :param unicode key: SSH public key string.
    :raises ValueError: when a given user doesn't exist.
    """
    keyfile = _user.get(user)["home"] + "/.ssh/authorized_keys"
    if file.exists(keyfile):
        if key not in file.read(keyfile):
            file.append(keyfile, key)
    else:
        file.write(keyfile, key)
