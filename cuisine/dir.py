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
from .file import attrs


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
