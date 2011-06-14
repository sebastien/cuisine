# -*- coding: utf-8 -*-
"""
    cuisine.file
    ~~~~~~~~~~~~

    Helper functions for working with remote files.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

import bz2
import base64

from fabric.api import hide
from fabric.context_managers import settings

from . import run


def exists(location):
    """Return ``True`` if there is a *remote* file at the given
    location and ``False`` otherwise.
    """
    return run("test -f %r && echo OK ; true" % location) == "OK"


def ensure(location):
    """Ensures that there's a file at a given location."""
    run("touch %r" % location)


def attrs(location, mode=None, owner=None, group=None, recursive=False):
    """Updates the mode, owner and group for the remote file at the given
    location.

    :raises ValueError: there's no file at a given location.
    """
    if not exists(location):
        raise ValueError("%r doesn't exist" % location)

    recursive = recursive and "-R " or ""
    if mode:  run("chmod %s %s '%s'" % (recursive, mode,  location))
    if owner: run("chown %s %s '%s'" % (recursive, owner, location))
    if group: run("chgrp %s %s '%s'" % (recursive, group, location))


def read(location):
    """Reads a *remote* file at the given location.

    :raises ValueError: there's no file at a given location.
    """
    if not exists(location):
        raise ValueError("%r doesn't exist" % location)

    return run("cat %r" % location)


def write(location, content, **acl):
    """Writes a given content to the file at the given remote location,
    and optionally sets it's access rights.
    """
    # Hides the output, which is especially important
    with settings(hide("warning", "running", "stdout"), warn_only=True):
        content = base64.b64encode(bz2.compress(content))
        run("echo %r | base64 -d | bzcat > \"%s\"" % (content, location))
        attrs(location, **acl)


def append(location, content, **acl):
    """Appends a given content to the remote file at the given location;
    and optionally updates it's access rights.

    :raises ValueError: there's no file at a given location.
    """
    if not exists(location):
        raise ValueError("%r doesn't exist" % location)

    run("echo %r | base64 -d >> \"%s\"" % (base64.b64encode(content), location))
    attrs(location, **acl)


def update(location, func=lambda x: x):
    """Updates a remote file at a given location by calling `func` for
    it's contents and writing back the result. For instance, if you'd
    like to convert a file to UPPERCASE, do:

    >>> update("/tmp/foo", lambda l: l.upper())

    :raises ValueError: there's no file at a given location.
    """
    contents = base64.b64encode(func(read(location)))
    run("echo %r | base64 -d > \"%s\"" % (contents, location))
