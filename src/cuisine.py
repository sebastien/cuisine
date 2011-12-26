# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Project   : Cuisine - Functions to write Fabric recipies
# -----------------------------------------------------------------------------
# Author    : Sebastien Pierre                            <sebastien@ffctn.com>
# Author    : Thierry Stiegler   (gentoo port)     <thierry.stiegler@gmail.com>
# Author    : Jim McCoy (distro checks and rpm port)      <jim.mccoy@gmail.com>
# License   : Revised BSD License
# -----------------------------------------------------------------------------
# Creation  : 26-Apr-2010
# Last mod  : 31-Oct-2011
# -----------------------------------------------------------------------------

"""
`cuisine` makes it easy to write automatic server installation
and configuration recipies by wrapping common administrative tasks
(installing packages, creating users and groups) in Python
functions.

`cuisine` is designed to work with Fabric and provide all you
need for getting your new server up and running in minutes.

Note, that right now, Cuisine only supports Debian-based Linux
systems.

See also:

- Deploying Django with Fabric
  <http://lethain.com/entry/2008/nov/04/deploying-django-with-fabric>

- Notes on Python Fabric 0.9b1
  <http://www.saltycrane.com/blog/2009/10/notes-python-fabric-09b1>`_

- EC2, fabric, and "err: stdin: is not a tty"
  <http://blog.markfeeney.com/2009/12/ec2-fabric-and-err-stdin-is-not-tty.html>`_

:copyright: (c) 2011 by Sébastien Pierre, see AUTHORS for more details.
:license:   BSD, see LICENSE for more details.
"""

import base64, bz2, crypt, hashlib, os, random, re, string, tempfile, subprocess
import fabric, fabric.api, fabric.operations, fabric.context_managers

VERSION     = "0.1.1"

RE_SPACES   = re.compile("[\s\t]+")
MAC_EOL     = "\n"
UNIX_EOL    = "\n"
WINDOWS_EOL = "\r\n"
# FIXME: MODE should be in the fabric env, as this is definitely not thread-safe
MODE_USER   = "user"
MODE_SUDO   = "sudo"
MODE        = MODE_USER


# context managers and wrappers around fabric's run/sudo; used to
# either execute cuisine functions with sudo or as current user:
#
# with mode_sudo():
#     pass

class mode_user(object):
    """Cuisine functions will be executed as the current user."""

    def __init__(self):
        global MODE
        self._old_mode = MODE
        MODE = MODE_USER

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        global MODE
        MODE = self._old_mode


class mode_sudo(object):
    """Cuisine functions will be executed with sudo."""

    def __init__(self):
        global MODE
        self._old_mode = MODE
        MODE = MODE_SUDO

    def __enter__(self):
        pass

    def __exit__(self, *args, **kws):
        global MODE
        MODE = self._old_mode


def run(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the
    'cuisine.MODE' global to tell wether the command should be run as
    regular user or sudo."""
    if MODE == MODE_SUDO:
        return fabric.api.sudo(*args, **kwargs)
    else:
        return fabric.api.run(*args, **kwargs)

def run_local(command):
    """A wrapper around subprocess"""
    pipe = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout
    res = pipe.read()
    # FIXME: Should stream the pipe, and only print it if fabric's properties allow it
    print res
    return pipe


def sudo(*args, **kwargs):
    """A wrapper to Fabric's run/sudo commands, using the
    'cuisine.MODE' global to tell wether the command should be run as
    regular user or sudo."""
    return fabric.api.sudo(*args, **kwargs)


### decorators

def multiargs(function):
    """Decorated functions will be 'map'ed to every element of the
    first argument if it is a list or a tuple, otherwise the function
    will execute normally."""
    def wrapper(*args, **kwargs):
        if len(args) == 0:
            return function()
        arg = args[0]
        args = args[1:]
        if type(arg) in (tuple, list):
            return map(lambda _: function(_, *args, **kwargs), arg)
        else:
            return function(arg, *args, **kwargs)
    return wrapper


### text_<operation> functions

def text_detect_eol(text):
    # FIXME: Should look at the first line
    if text.find("\r\n") != -1:
        return WINDOWS_EOL
    elif text.find("\n") != -1:
        return UNIX_EOL
    elif text.find("\r") != -1:
        return MAC_EOL
    else:
        return "\n"


def text_get_line(text, predicate):
    """Returns the first line that matches the given predicate."""
    for line in text.split("\n"):
        if predicate(line):
            return line
    return ""


def text_normalize(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub(" ", text).strip()


def text_nospace(text):
    """Converts tabs and spaces to single space and strips the text."""
    return RE_SPACES.sub("", text).strip()


def text_replace_line(text, old, new, find=lambda old, new: old == new,
                      process=lambda _: _):
    """Replaces lines equal to 'old' with 'new', returning the new
    text and the count of replacements."""
    res = []
    replaced = 0
    eol = text_detect_eol(text)
    for line in text.split(eol):
        if find(process(line), process(old)):
            res.append(new)
            replaced += 1
        else:
            res.append(line)
    return eol.join(res), replaced


def text_ensure_line(text, *lines):
    """Ensures that the given lines are present in the given text,
    otherwise appends the lines that are not already in the text at
    the end of it."""
    eol = text_detect_eol(text)
    res = list(text.split(eol))
    for line in lines:
        assert line.find(eol) == -1, \
               "No EOL allowed in lines parameter: " + repr(line)
        found = False
        for l in res:
            if l == line:
                found = True
                break
        if not found:
            res.append(line)
    return eol.join(res)


def text_strip_margin(text, margin="|"):
    res = []
    eol = text_detect_eol(text)
    for line in text.split(eol):
        l = line.split(margin, 1)
        if len(l) == 2:
            _, line = l
            res.append(line)
    return eol.join(res)


def text_template(text, variables):
    """Substitutes '${PLACEHOLDER}'s within the text with the
    corresponding values from variables."""
    template = string.Template(text)
    return template.safe_substitute(variables)


### file_<operation> functions

def file_local_read(location):
    """Reads a *local* file from the given location, expanding '~' and
    shell variables."""
    p = os.path.expandvars(os.path.expanduser(location))
    f = file(p, 'rb')
    t = f.read()
    f.close()
    return t


def file_read(location):
    """Reads the *remote* file at the given location."""
    # NOTE: We use base64 here to be sure to preserve the encoding (UNIX/DOC/MAC) of EOLs
    return base64.b64decode(run('cat "%s" | base64' % (location)))


def file_exists(location):
    """Tests if there is a *remote* file at the given location."""
    return run('test -f "%s" && echo OK ; true' % (location)) == "OK"


def file_attribs(location, mode=None, owner=None, group=None,
                 recursive=False):
    """Updates the mode/owner/group for the remote file at the given
    location."""
    recursive = recursive and "-R " or ""
    if mode:
        run('chmod %s %s "%s"' % (recursive, mode,  location))
    if owner:
        run('chown %s %s "%s"' % (recursive, owner, location))
    if group:
        run('chgrp %s %s "%s"' % (recursive, group, location))


def file_attribs_get(location):
    """Return mode, owner, and group for remote path.
    Return mode, owner, and group if remote path exists, 'None'
    otherwise.
    """
    if file_exists(location):
        fs_check = run('stat %s %s' % (location, '--format="%a %U %G"'))
        (mode, owner, group) = fs_check.split(' ')
        return {'mode': mode, 'owner': owner, 'group': group}
    else:
        return None

def file_write(location, content, mode=None, owner=None, group=None):
    """Writes the given content to the file at the given remote
    location, optionally setting mode/owner/group."""
    # FIXME: Big files are never transferred properly!
    # Gets the content signature and write it to a secure tempfile
    sig            = hashlib.sha256(content).hexdigest()
    fd, local_path = tempfile.mkstemp()
    os.write(fd, content)
    # Upload the content if necessary
    if not file_exists(location) or sig != file_sha256(location):
        fabric.operations.put(local_path, location, use_sudo=(MODE == MODE_SUDO))
    # Remove the local temp file
    os.close(fd)
    os.unlink(local_path)
    # Ensure that the signature matches
    assert sig == file_sha256(location)

def file_ensure(location, mode=None, owner=None, group=None,
                 recursive=False):
    """Updates the mode/owner/group for the remote file at the given
    location."""
    if file_exists(location):
        file_attribs(location,mode=mode,owner=owner,group=group)
    else:
        file_write(location,"",mode=mode,owner=owner,group=group)

def file_upload(remote, local):
    """Uploads the local file to the remote location only if the remote location does not
    exists or the content are different."""
    # FIXME: Big files are never transferred properly!
    f       = file(local, 'rb')
    content = f.read()
    f.close()
    sig     = hashlib.sha256(content).hexdigest()
    if not file_exists(remote) or sig != file_sha256(remote):
        fabric.operations.put(local, remote, use_sudo=(MODE == MODE_SUDO))

def file_update(location, updater=lambda x: x):
    """Updates the content of the given by passing the existing
    content of the remote file at the given location to the 'updater'
    function.

    For instance, if you'd like to convert an existing file to all
    uppercase, simply do:

    >   file_update("/etc/myfile", lambda _:_.upper())
    """
    assert file_exists(location), "File does not exists: " + location
    new_content = updater(file_read(location))

    assert type(new_content) in (str, unicode, fabric.operations._AttributeString), \
           "Updater must be like (string)->string, got: %s() = %s" % \
           (updater, type(new_content))
    run('echo "%s" | base64 -d > "%s"' %
        (base64.b64encode(new_content), location))


def file_append(location, content, mode=None, owner=None, group=None):
    """Appends the given content to the remote file at the given
    location, optionally updating its mode/owner/group."""
    run('echo "%s" | base64 -d >> "%s"' %
        (base64.b64encode(content), location))
    file_attribs(location, mode, owner, group)

def file_link(source, destination, symbolic=True, mode=None, owner=None, group=None):
    """Creates a (symbolic) link between source and destination on the remote host,
    optionally setting its mode/owner/group."""
    if symbolic:
        run('ln -sf "%s" "%s"' % (source, destination))
    else:
        run('ln -f "%s" "%s"' % (source, destination))
    file_attribs(destination, mode, owner, group)

def file_sha256(location):
    """Returns the SHA-256 sum (as a hex string) for the remote file at the given location"""
    return run('sha256sum "%s" | cut -d" " -f1' % (location))

# TODO: From McCoy's version, consider merging
# def file_append( location, content, use_sudo=False, partial=False, escape=True):
#       """Wrapper for fabric.contrib.files.append."""
#       fabric.contrib.files.append(location, content, use_sudo, partial, escape)


### dir_<operation> functions

def dir_attribs(location, mode=None, owner=None, group=None, recursive=False):
    """Updates the mode/owner/group for the given remote directory."""
    file_attribs(location, mode, owner, group, recursive)


def dir_exists(location):
    """Tells if there is a remote directory at the given location."""
    return run('test -d "%s" && echo OK ; true' % (location)).endswith("OK")


def dir_ensure(location, recursive=False, mode=None, owner=None, group=None):
    """Ensures that there is a remote directory at the given location,
    optionnaly updating its mode/owner/group.

    If we are not updating the owner/group then this can be done as a single
    ssh call, so use that method, otherwise set owner/group after creation."""
    if mode:
        mode_arg = "-m %s" % (mode)
    else:
        mode_arg = ""
    run('test -d "%s" || mkdir %s %s "%s" && echo OK ; true' %
        (location, recursive and "-p" or "", mode_arg, location))
    if owner or group:
        dir_attribs(location, owner=owner, group=group)


### package_<operation> functions

def package_update(package=None):
    """Updates the package database (when no argument) or update the package
    or list of packages given as argument."""
    if package == None:
        sudo("apt-get --yes update")
    else:
        if type(package) in (list, tuple):
            package = " ".join(package)
        sudo("apt-get --yes upgrade " + package)


def package_install(package, update=False):
    """Installs the given package/list of package, optionnaly updating
    the package database."""
    if update:
        sudo("apt-get --yes update")
    if type(package) in (list, tuple):
        package = " ".join(package)
    sudo("apt-get --yes install %s" % (package))


@multiargs
def package_ensure(package):
    """Tests if the given package is installed, and installes it in
    case it's not already there."""
    status = run("dpkg-query -W -f='${Status}' %s ; true" % package)
    if status.find("not-installed") != -1 or status.find("installed") == -1:
        package_install(package)
        return False
    else:
        return True


### command_<operation> functions

def command_check(command):
    """Tests if the given command is available on the system."""
    return run("which '%s' >& /dev/null && echo OK ; true" % command).endswith("OK")


def command_ensure(command, package=None):
    """Ensures that the given command is present, if not installs the
    package with the given name, which is the same as the command by
    default."""
    if package is None:
        package = command
    if not command_check(command):
        package_install(package)
    assert command_check(command), \
           "Command was not installed, check for errors: %s" % (command)


### user_<operation> functions

def user_create(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                uid_min=None, uid_max=None):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = ["-m"]
    if passwd:
        method = 6
        saltchars = string.ascii_letters + string.digits + './'
        salt = ''.join([random.choice(saltchars) for x in range(8)])
        passwd_crypted = crypt.crypt(passwd, '$%s$%s' % (method, salt))
        options.append("-p '%s'" % (passwd_crypted))
    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u '%s'" % (uid))
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-K UID_MIN='%s'" % (uid_min))
    if uid_max:
        options.append("-K UID_MAX='%s'" % (uid_max))
    sudo("useradd %s '%s'" % (" ".join(options), name))


def user_check(name):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists."""
    d = sudo("cat /etc/passwd | egrep '^%s:' ; true" % (name))
    s = sudo("cat /etc/shadow | egrep '^%s:' | awk -F':' '{print $2}'" % (name))
    results = {}
    if d:
        d = d.split(":")
        results = dict(name=d[0], uid=d[2], gid=d[3], home=d[5], shell=d[6])
    if s:
        results['passwd'] = s
    if results:
        return results
    else:
        return None


def user_ensure(name, passwd=None, home=None, uid=None, gid=None, shell=None):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""
    d = user_check(name)
    if not d:
        user_create(name, passwd, home, uid, gid, shell)
    else:
        options = []
        if passwd != None and d.get('passwd') != None:
            method, salt = d.get('passwd').split('$')[1:3]
            passwd_crypted = crypt.crypt(passwd, '$%s$%s' % (method, salt))
            if passwd_crypted != d.get('passwd'):
                options.append("-p '%s'" % (passwd_crypted))
        if passwd != None and d.get('passwd') is None:
            # user doesn't have passwd
            method = 6
            saltchars = string.ascii_letters + string.digits + './'
            salt = ''.join([random.choice(saltchars) for x in range(8)])
            passwd_crypted = crypt.crypt(passwd, '$%s$%s' % (method, salt))
            options.append("-p '%s'" % (passwd_crypted))
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if options:
            sudo("usermod %s '%s'" % (" ".join(options), name))


### group_<operation> functions

def group_create(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""
    options = []
    if gid:
        options.append("-g '%s'" % (gid))
    sudo("groupadd %s '%s'" % (" ".join(options), name))


def group_check(name):
    """Checks if there is a group defined with the given name,
    returning its information as a
    '{"name":<str>,"gid":<str>,"members":<list[str]>}' or 'None' if
    the group does not exists."""
    group_data = run("cat /etc/group | egrep '^%s:' ; true" % (name))
    if group_data:
        name, _, gid, members = group_data.split(":", 4)
        return dict(name=name, gid=gid,
                    members=tuple(m.strip() for m in members.split(",")))
    else:
        return None


def group_ensure(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""
    d = group_check(name)
    if not d:
        group_create(name, gid)
    else:
        if gid != None and d.get("gid") != gid:
            sudo("groupmod -g %s '%s'" % (gid, name))


def group_user_check(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""
    d = group_check(group)
    if d is None:
        return False
    else:
        return user in d["members"]


def group_user_add(group, user):
    """Adds the given user/list of users to the given group/groups."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if not group_user_check(group, user):
        sudo("usermod -a -G '%s' '%s'" % (group, user))


def group_user_ensure(group, user):
    """Ensure that a given user is a member of a given group."""
    d = group_check(group)
    if user not in d["members"]:
        group_user_add(group, user)


### ssh_<operation> functions

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
        file_attribs(home + "/.ssh/id_%s.pub" % keytype, owner=user, group=user)
        return False
    else:
        return True


def ssh_authorize(user, key):
    """Adds the given key to the '.ssh/authorized_keys' for the given
    user."""
    d = user_check(user)
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
        file_write(keyf, key)
        return False


### miscellaneous (utility/helper) functions

def upstart_ensure(name):
    """Ensures that the given upstart service is running, restarting
    it if necessary"""
    if sudo("service %s status" % name).find("is running") >= 0:
        sudo("service %s restart" % name)
    else:
        sudo("service %s start" % name)

def system_uuid_alias_add():
    """Adds system UUID alias to /etc/hosts.

    Some tools/processes rely/want the hostname as an alias in
    /etc/hosts e.g. `127.0.0.1 localhost <hostname>`.

    """
    with mode_sudo():
        with cd('/etc'):
            old = "127.0.0.1 localhost"
            new = old + " " + system_uuid()
            file_update('hosts', lambda x: text_replace_line(x, old, new)[0])


def system_uuid():
    """Gets a machines UUID (Universally Unique Identifier)."""
    return sudo('dmidecode -s system-uuid | tr "[A-Z]" "[a-z]"')

# EOF - vim: ts=4 sw=4 et
