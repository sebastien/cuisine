# -*- coding: utf-8 -*-
"""
    cuisine.package
    ~~~~~~~~~~~~~~~

    Helper functions for working with package managers. Currently the
    only one support is ``aptitude``.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

from fabric.api import sudo

from . import run, multiargs


def update():
    """Updates package database."""
    sudo("apt-get --yes update")


def upgrade(*packages):
    """Updates a given list of packages.

    :param list packages: list of packages to update.
    """
    if not packages:
        raise ValueError("Nothing to update.")

    sudo("apt-get --yes upgrade " + " ".join(packages))


def install(*packages):
    """Installs a given list of packages.

    :param list packages: list of packages to install.
    """
    sudo("apt-get --yes install " + " ".join(packages))


@multiargs
def ensure(package):
    """Ensures a given package is installed."""
    if "installed" not in \
        run("dpkg-query -W -f='${Status}' %s ; true" % package):
        install(package)
