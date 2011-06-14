# -*- coding: utf-8 -*-
"""
    cuisine.dir
    ~~~~~~~~~~~

    Helper functions for working with remote directories.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

__all__ = ["attrs", "exists", "ensure"]

from fabric.api import sudo

from . import run


def attrs(location, mode=None, owner=None, group=None, recursive=False):
    """Updates the mode, owner and group for the remote directory at
    the given location.

    :raises ValueError: when directory doesn't exist.
    """
    if not exists(location):
        raise ValueError("Directory %r doesn't exist." % location)

    recursive = recursive and "-R " or ""
    if mode:  run("chmod %s %s %r" % (recursive, mode,  location))
    if owner: run("chown %s %s %r" % (recursive, owner, location))
    if group: run("chgrp %s %s %r" % (recursive, group, location))


def exists(location):
    """Return ``True`` if there is a *remote* directory at the given
    location and ``False`` otherwise.
    """
    return run("test -d %r && echo OK ; true" % location) == "OK"


def ensure(location, **acl):
    """Ensures that there is a remote directory at the given location,
    optionally updating its access rights.

    If we are not updating the owner/group then this can be done as a single
    ssh call, so use that method, otherwise set owner/group after creation."""
    sudo("(test -d %r || mkdir -p %s '%s') && echo OK ; true" % \
         (location, location))
    attrs(location, **acl)
