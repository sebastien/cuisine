# -*- coding: utf-8 -*-
"""
    cuisine.group
    ~~~~~~~~~~~~~

    Helper functions for working with remote groups.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

__all__ = ["create", "exists", "get", "ensure", "has", "add_user", "ensure_user"]

import os

from fabric.api import sudo

from . import multiargs, run, file


def create(name, gid=None):
    """Creates a new remote group.

    :param unicode name: name for the group being created.
    :param int gid: numerical value of the group's ID.
    :raises ValueError: if a group with a given name already exists.
    """
    if exists(name):
        raise ValueError("Group %r already exists.")

    if gid:
        sudo("groupadd -g %r %s" % (gid, name))
    else:
        sudo("group add %s" % name)


def exists(name):
    """Returns ``True`` if there is a remote group with a given name
    and ``False`` otherwise.
    """
    return bool(run("cat /etc/group | egrep '^%s:' ; true" % name))


def get(name, silent=True):
    """Returns group data from ``/etc/group`` on the remote machine.

    :param unicode name: name of the group to fetch data for.
    :param bool silent: if ``False`` :exc:`ValueError` is raised when
                        no group is found for a given name otherwise
                        ``None`` is returned.
    """
    data = run("cat /etc/group | egrep '^%s:' ; true" % name)
    if data:
        data = dict(zip(["name", "password", "gid", "members"], data))
        data["members"] = [m.strip() for m in data["members"]]
        return data
    elif not silent:
        raise ValueError("Group %r doesn't exist.")


def ensure(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists.
    """
    data = get(name)
    if not data:
        create(name, gid)
    elif gid is not None and data.get("gid") is not gid:
        sudo("groupmod -g %s %r" % (gid, name))


def has(group, user):
    """Return ``True`` if a given user is a member of the given group
    and ``False`` otherwise.

    :raises ValueError: if a group with a given name doesn't exist.
    """
    return user in get(group, silent=False)["members"]


@multiargs
def add_user(group, user):
    """Adds the given user to a given group.

    :raises ValueError: if a group with a given name doesn't exist.
    """
    if not has(group, user):
        lines = []
        for line in file.read("/etc/group").splitlines():
            if line.startswith(group + ":"):
                if line.strip().endswith(":"):
                    line = line + user
                else:
                    line = line + "," + user
            lines.append(line)

        file.write("/etc/group", os.sep.join(lines))


def ensure_user(group, user):
    """Ensures that a given user is a member of a given group.

    :raises ValueError: if a group with a given name doesn't exist.
    """
    if user not in get(group)["members"]:
        add_user(group, user)
