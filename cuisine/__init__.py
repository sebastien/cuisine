# -*- coding: utf-8 -*-
"""
    cusisine
    ~~~~~~~~

    ``cuisine`` makes it easy to write automatic server installation and
    configuration recipies by wrapping common administrative tasks
    (installing packages, creating users and groups) in Python functions.

    ``cuisine`` is designed to work with Fabric and provide all you need
    for getting your new server up and running in minutes.

    Note, that right now, Cuisine only supports Debian-based Linux systems.

    .. seealso::

       `Deploying Django with Fabric
       <http://lethain.com/entry/2008/nov/04/deploying-django-with-fabric>`_

       `Notes on Python Fabric 0.9b1
       <http://www.saltycrane.com/blog/2009/10/notes-python-fabric-09b1>`_

       `EC2, fabric, and "err: stdin: is not a tty"
       <http://blog.markfeeney.com/2009/12/ec2-fabric-and-err-stdin-is-not-tty.html>`_

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

import os
from functools import wraps

import fabric
import fabric.api
import fabric.context_managers


MODE      = "user"


def mode_user():
	"""Cuisine functions will be executed as the current user."""
	global MODE
	MODE = "user"


def mode_sudo():
	"""Cuisine functions will be executed with sudo."""
	global MODE
	MODE = "sudo"


def run(*args, **kwargs):
	"""A wrapper around :func:`~fabric.api.sudo` and
    :func:`~fabric.api.run`, which uses an appropriate command, based
    on the value of ``cuisine.MOD`` global.
    """
	if MODE == "sudo":
		return fabric.api.sudo(*args, **kwargs)
	else:
		return fabric.api.run(*args, **kwargs)

sudo = fabric.api.sudo


def multiargs(func):
    """Decorator changing the decorated function to accept multiple
    arguments. When called with a sequence type as first argument,
    applies the decorated function to each of the sequence items,
    otherwise executes it `normaly` (i.e. with the given arguments).

    >>> @multiargs
    ... def foo(arg):
    ...    print(arg)
    ...
    >>> foo("bar")
    bar
    >>> foo(["bar", "baz"])
    bar
    baz
    [None, None]
    """
    @wraps(func)
    def inner(*args, **kwargs):
        if args and isinstance(args[0], (list, tuple)):
            return map(lambda a: func(a, *args[1:], **kwargs), args[0])
        else:
            return func(*args, **kwargs)
    return inner


def local_read( location ):
	"""Reads a *local* file from the given location, expanding '~' and shell variables."""
	p = os.path.expandvars(os.path.expanduser(location))
	f = file(p, 'rb')
	t = f.read()
	f.close()
	return t


def command_check( command ):
	"""Tests if the given command is available on the system."""
	return run("which '%s' >& /dev/null && echo OK ; true" % command).endswith("OK")


def command_ensure( command, package=None ):
	"""Ensures that the given command is present, if not installs the package with the given
	name, which is the same as the command by default."""
	from .package import install

	if package is None: package = command
	if not command_check(command): install(package)
	assert command_check(command), "Command was not installed, check for errors: %s" % (command)


def upstart_ensure( name ):
	"""Ensures that the given upstart service is running, restarting it if necessary"""
	if sudo("status "+ name ).find("/running") >= 0:
		sudo("restart " + name)
	else:
		sudo("start " + name)


# EOF - vim: ts=4 sw=4 noet
