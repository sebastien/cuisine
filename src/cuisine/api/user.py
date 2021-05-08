from ..decorators import dispatch, requires

# =============================================================================
#
# USER OPERATIONS
#
# =============================================================================


@dispatch('user')
def user_passwd(name, passwd, encrypted_passwd=True):
    """Sets the given user password. Password is expected to be encrypted by default."""


@dispatch('user')
def user_create(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""


@dispatch('user')
def user_check(name=None, uid=None, need_passwd=True):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists.
    need_passwd (Boolean) indicates if password to be included in result or not.
            If set to True it parses 'getent shadow' and needs sudo access
    """


@dispatch('user')
def user_ensure(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""


@dispatch('user')
def user_remove(name, rmhome=None):
    """Removes the user with the given name, optionally
    removing the home directory and mail spool."""

# =============================================================================
# Linux support (useradd, usermod)
# =============================================================================


def user_passwd_linux(name, passwd, encrypted_passwd=True):
    """Sets the given user password. Password is expected to be encrypted by default."""
    encoded_password = base64.b64encode("%s:%s" % (name, passwd))
    if encrypted_passwd:
        sudo("usermod -p '%s' %s" % (passwd, name))
    else:
        # NOTE: We use base64 here in case the password contains special chars
        # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
        sudo("echo %s | openssl base64 -A -d | chpasswd" %
             (shell_safe(encoded_password)))


def user_create_linux(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                      uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u '%s'" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-K UID_MIN='%s'" % (uid_min))
    if uid_max:
        options.append("-K UID_MAX='%s'" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("useradd %s '%s'" % (" ".join(options), name))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


@requires("pw")
def user_create_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                    uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u %s" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-u %s," % (uid_min))
    if uid_max:
        options.append("%s" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("pw useradd -n %s %s" % (name, " ".join(options)))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


@requires("getent", "egrep", "true", "awk")
def user_check_linux(name=None, uid=None, need_passwd=True):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists.
    need_passwd (Boolean) indicates if password to be included in result or not.
            If set to True it parses 'getent shadow' and needs sudo access
    """
    assert name != None or uid != None,     "user_check: either `uid` or `name` should be given"
    assert name is None or uid is None, "user_check: `uid` and `name` both given, only one should be provided"
    if name != None:
        d = run("getent passwd | egrep '^%s:' ; true" % (name))
    elif uid != None:
        d = run("getent passwd | egrep '^.*:.*:%s:' ; true" % (uid))
    results = {}
    s = None
    if d:
        d = d.split(":")
        assert len(d) >= 7, "passwd entry returned by getent is expected to have at least 7 fields, got %s in: %s" % (
            len(d), ":".join(d))
        results = dict(name=d[0], uid=d[2], gid=d[3],
                       fullname=d[4], home=d[5], shell=d[6])
        if need_passwd:
            s = sudo(
                "getent shadow | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
            if s:
                results['passwd'] = s
    if results:
        return results
    else:
        return None


def user_ensure_linux(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""
    d = user_check(name)
    if not d:
        user_create(name, passwd, home, uid, gid, shell,
                    fullname=fullname, encrypted_passwd=encrypted_passwd)
    else:
        options = []
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if fullname != None and d.get("fullname") != fullname:
            options.append("-c '%s'" % fullname)
        if options:
            sudo("usermod %s '%s'" % (" ".join(options), name))
        if passwd:
            user_passwd(name=name, passwd=passwd,
                        encrypted_passwd=encrypted_passwd)


def user_remove_linux(name, rmhome=None):
    """Removes the user with the given name, optionally
    removing the home directory and mail spool."""
    options = ["-f"]
    if rmhome:
        options.append("-r")
    sudo("userdel %s '%s'" % (" ".join(options), name))

# =============================================================================
# BSD support (pw useradd, userdel )
# =============================================================================


def user_passwd_bsd(name, passwd, encrypted_passwd=True):
    """Sets the given user password. Password is expected to be encrypted by default."""
    encoded_password = base64.b64encode("%s:%s" % (name, passwd))
    if encrypted_passwd:
        sudo("pw usermod '%s' -p %s" % (name, passwd))
    else:
        # NOTE: We use base64 here in case the password contains special chars
        # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
        sudo("echo %s | openssl base64 -A -d | chpasswd" %
             (shell_safe(encoded_password)))


def user_create_passwd_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                           uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u '%s'" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-K UID_MIN='%s'" % (uid_min))
    if uid_max:
        options.append("-K UID_MAX='%s'" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("useradd %s '%s'" % (" ".join(options), name))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


def user_create_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
                    uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
    """Creates the user with the given name, optionally giving a
    specific password/home/uid/gid/shell."""
    options = []

    if home:
        options.append("-d '%s'" % (home))
    if uid:
        options.append("-u %s" % (uid))
    # if group exists already but is not specified, useradd fails
    if not gid and group_check(name):
        gid = name
    if gid:
        options.append("-g '%s'" % (gid))
    if shell:
        options.append("-s '%s'" % (shell))
    if uid_min:
        options.append("-u %s," % (uid_min))
    if uid_max:
        options.append("%s" % (uid_max))
    if fullname:
        options.append("-c '%s'" % (fullname))
    if createhome:
        options.append("-m")
    sudo("pw useradd -n %s %s" % (name, " ".join(options)))
    if passwd:
        user_passwd(name=name, passwd=passwd,
                    encrypted_passwd=encrypted_passwd)


def user_check_bsd(name=None, uid=None, need_passwd=True):
    """Checks if there is a user defined with the given name,
    returning its information as a
    '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
    or 'None' if the user does not exists.
    need_passwd (Boolean) indicates if password to be included in result or not.
            If set to True it parses 'getent passwd' and needs sudo access
    """
    assert name != None or uid != None,     "user_check: either `uid` or `name` should be given"
    assert name is None or uid is None, "user_check: `uid` and `name` both given, only one should be provided"
    if name != None:
        d = run("getent passwd | egrep '^%s:' ; true" % (name))
    elif uid != None:
        d = run("getent passwd | egrep '^.*:.*:%s:' ; true" % (uid))
    results = {}
    s = None
    if d:
        d = d.split(":")
        assert len(d) >= 7, "passwd entry returned by getent is expected to have at least 7 fields, got %s in: %s" % (
            len(d), ":".join(d))
        results = dict(name=d[0], uid=d[2], gid=d[3],
                       fullname=d[4], home=d[5], shell=d[6])
        if need_passwd:
            s = sudo(
                "getent passwd | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
            if s:
                results['passwd'] = s
    if results:
        return results
    else:
        return None


def user_ensure_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
    """Ensures that the given users exists, optionally updating their
    passwd/home/uid/gid/shell."""
    d = user_check(name)
    if not d:
        user_create(name, passwd, home, uid, gid, shell,
                    fullname=fullname, encrypted_passwd=encrypted_passwd)
    else:
        options = []
        if home != None and d.get("home") != home:
            options.append("-d '%s'" % (home))
        if uid != None and d.get("uid") != uid:
            options.append("-u '%s'" % (uid))
        if gid != None and d.get("gid") != gid:
            options.append("-g '%s'" % (gid))
        if shell != None and d.get("shell") != shell:
            options.append("-s '%s'" % (shell))
        if fullname != None and d.get("fullname") != fullname:
            options.append("-c '%s'" % fullname)
        if options:
            sudo("pw usermod %s '%s'" % (name, " ".join(options)))
        if passwd:
            user_passwd(name=name, passwd=passwd,
                        encrypted_passwd=encrypted_passwd)


def user_remove_bsd(name, rmhome=None):
    """Removes the user with the given name, optionally
    removing the home directory and mail spool."""
    options = ["-f"]
    if rmhome:
        options.append("-r")
    sudo("pw userdel %s '%s'" % (" ".join(options), name))


# EOF
