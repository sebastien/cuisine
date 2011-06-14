# -*- coding: utf-8 -*-
"""
    cuisine.user
    ~~~~~~~~~~~~

    Helper functions for working with remote users.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

__all__ = ["create", "exists", "get", "ensure"]

import crypt
import random
import string

from fabric.api import sudo


def create(name, password=None, home=None, uid=None, gid=None, shell=None):
    """Creates a remote user with a given name."""
    options = ["-m"]

    if password:
        method = 6
        saltchars = string.ascii_letters + string.digits + "./"
        salt = "".join(random.choice(saltchars) for x in range(8))
        options.append(
            "-p %r" % crypt.crypt(password, '$%s$%s' % (method, salt)))

    if home: options.append("-d %r" % home)
    if uid: options.append("-u %r" % uid)
    if gid: options.append("-g %r" % gid)
    if shell: options.append("-s %r" % shell)
    sudo("useradd %s %r" % (" ".join(options), name))


def exists(name):
    """Returns ``True`` if there is a remote user with a given name
    and ``False`` otherwise.
    """
    return bool(sudo("cat /etc/passwd | egrep '^%s:' ; true" % name))


def get(name, silent=True):
    """Returns user data from ``/etc/{passwd,shadow}`` on the remote
    machine.

    :param unicode name: name of the user to fetch data for.
    :param bool silent: if ``False`` :exc:`ValueError` is raised when
                        no user is found for a given name otherwise
                        ``None`` is returned.
    """
    data = sudo("cat /etc/passwd | egrep '^%s:' ; true" % name)
    if data:
        data = dict(zip(["name", "password", "uuid", "gid", "home", "shekk"],
                    data.split(":")))

        data["password"] = sudo("cat /etc/shadow | egrep '^%s:' | "
                                "awk -F':' '{print $2}'" % name)
        return data
    elif not silent:
        raise ValueError("User %r doesn't exist." % name)


def ensure(name, password=None, home=None, uid=None, gid=None, shell=None):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell.

    TODO: split this into ensure() and update()?
    """
    data = get(name)
    if not data:
        create(name, password, home, uid, gid, shell)
    else:
        # FIXME: oh my, this is mess ...
        d = data
        options=[]
        if password != None and d.get('password') != None:
            method, salt = d.get('password').split('$')[1:3]
            password_crypted = crypt.crypt(password, '$%s$%s' % (method, salt))
            if password_crypted != d.get('password'):
                options.append("-p '%s'" % (password_crypted))
        if password != None and d.get('password') is None:
            # user doesn't have password
            method = 6
            saltchars = string.ascii_letters + string.digits + './'
            salt = ''.join([random.choice(saltchars) for x in range(8)])
            password_crypted = crypt.crypt(password, '$%s$%s' % (method, salt))
            options.append("-p '%s'" % (password_crypted))
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid  != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid  != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if options:
            sudo("usermod %s '%s'" % (" ".join(options), name))
