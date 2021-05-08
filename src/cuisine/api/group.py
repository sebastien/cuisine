from ..decorators import dispatch

# =============================================================================
#
# GROUP OPERATIONS
#
# =============================================================================


@dispatch('group')
def group_create(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""


@dispatch('group')
def group_check(name):
    """Checks if there is a group defined with the given name,
    returning its information as a
    '{"name":<str>,"gid":<str>,"members":<list[str]>}' or 'None' if
    the group does not exists."""


@dispatch('group')
def group_ensure(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""


@dispatch('group')
def group_user_check(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""


@dispatch('group')
def group_user_add(group, user):
    """Adds the given user/list of users to the given group/groups."""


@dispatch('group')
def group_user_ensure(group, user):
    """Ensure that a given user is a member of a given group."""


@dispatch('group')
def group_user_del(group, user):
    """remove the given user from the given group."""


@dispatch('group')
def group_remove(group=None, wipe=False):
    """ Removes the given group, this implies to take members out the group
    if there are any.  If wipe=True and the group is a primary one,
    deletes its user as well.
    """

# Linux support
#
# =============================================================================


def group_create_linux(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""
    options = []
    if gid:
        options.append("-g '%s'" % (gid))
    sudo("groupadd %s '%s'" % (" ".join(options), name))


def group_check_linux(name):
    """Checks if there is a group defined with the given name,
    returning its information as:
    '{"name":<str>,"gid":<str>,"members":<list[str]>}'
    or
    '{"name":<str>,"gid":<str>}' if the group has no members
    or
    'None' if the group does not exists."""
    group_data = run("getent group | egrep '^%s:' ; true" % (name))
    if len(group_data.split(":")) == 4:
        name, _, gid, members = group_data.split(":", 4)
        return dict(name=name, gid=gid,
                    members=tuple(m.strip() for m in members.split(",")))
    elif len(group_data.split(":")) == 3:
        name, _, gid = group_data.split(":", 3)
        return dict(name=name, gid=gid, members=(''))
    else:
        return None


def group_ensure_linux(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""
    d = group_check(name)
    if not d:
        group_create(name, gid)
    else:
        if gid != None and d.get("gid") != gid:
            sudo("groupmod -g %s '%s'" % (gid, name))


def group_user_check_linux(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""
    d = group_check(group)
    if d is None:
        return False
    else:
        return user in d["members"]


def group_user_add_linux(group, user):
    """Adds the given user/list of users to the given group/groups."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if not group_user_check(group, user):
        sudo("usermod -a -G '%s' '%s'" % (group, user))


def group_user_ensure_linux(group, user):
    """Ensure that a given user is a member of a given group."""
    d = group_check(group)
    if not d:
        group_ensure("group")
        d = group_check(group)
    if user not in d["members"]:
        group_user_add(group, user)


def group_user_del_linux(group, user):
    """remove the given user from the given group."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if group_user_check(group, user):
        group_for_user = run(
            "getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
        if group_for_user:
            sudo("usermod -G '%s' '%s'" % (",".join(group_for_user), user))
        else:
            sudo("usermod -G '' '%s'" % (user))


def group_remove_linux(group=None, wipe=False):
    """ Removes the given group, this implies to take members out the group
    if there are any.  If wipe=True and the group is a primary one,
    deletes its user as well.
    """
    assert group_check(group), "Group does not exist: %s" % (group)
    members_of_group = run("getent group %s | awk -F':' '{print $4}'" % group)
    members = members_of_group.split(",")
    is_primary_group = user_check(name=group)
    if wipe:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        if is_primary_group:
            user_remove(group)
        else:
            sudo("groupdel %s" % group)
    elif not is_primary_group:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        sudo("groupdel %s" % group)


# =============================================================================
#
# BSD support
#
# =============================================================================

def group_create_bsd(name, gid=None):
    """Creates a group with the given name, and optionally given gid."""
    options = []
    if gid:
        options.append("-g '%s'" % (gid))
    sudo("pw groupadd %s -n %s" % (" ".join(options), name))


def group_check_bsd(name):
    """Checks if there is a group defined with the given name,
    returning its information as:
    '{"name":<str>,"gid":<str>,"members":<list[str]>}'
    or
    '{"name":<str>,"gid":<str>}' if the group has no members
    or
    'None' if the group does not exists."""
    group_data = run("getent group | egrep '^%s:' ; true" % (name))
    if len(group_data.split(":")) == 4:
        name, _, gid, members = group_data.split(":", 4)
        return dict(name=name, gid=gid,
                    members=tuple(m.strip() for m in members.split(",")))
    elif len(group_data.split(":")) == 3:
        name, _, gid = group_data.split(":", 3)
        return dict(name=name, gid=gid, members=(''))
    else:
        return None


def group_ensure_bsd(name, gid=None):
    """Ensures that the group with the given name (and optional gid)
    exists."""
    d = group_check(name)
    if not d:
        group_create(name, gid)
    else:
        if gid != None and d.get("gid") != gid:
            sudo("pw groupmod -g %s -n %s" % (gid, name))


def group_user_check_bsd(group, user):
    """Checks if the given user is a member of the given group. It
    will return 'False' if the group does not exist."""
    d = group_check(group)
    if d is None:
        return False
    else:
        return user in d["members"]


def group_user_add_bsd(group, user):
    """Adds the given user/list of users to the given group/groups."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if not group_user_check(group, user):
        sudo("pw usermod '%s' -G '%s'" % (user, group))


def group_user_ensure_bsd(group, user):
    """Ensure that a given user is a member of a given group."""
    d = group_check(group)
    if not d:
        group_ensure("group")
        d = group_check(group)
    if user not in d["members"]:
        group_user_add(group, user)


def group_user_del_bsd(group, user):
    """remove the given user from the given group."""
    assert group_check(group), "Group does not exist: %s" % (group)
    if group_user_check(group, user):
        group_for_user = run(
            "getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
        if group_for_user:
            sudo("pw usermod -G '%s' '%s'" % (",".join(group_for_user), user))
        else:
            sudo("pw usermod -G '' '%s'" % (user))


def group_remove_bsd(group=None, wipe=False):
    """ Removes the given group, this implies to take members out the group
    if there are any.  If wipe=True and the group is a primary one,
    deletes its user as well.
    """
    assert group_check(group), "Group does not exist: %s" % (group)
    members_of_group = run("getent group %s | awk -F':' '{print $4}'" % group)
    members = members_of_group.split(",")
    is_primary_group = user_check(name=group)

    if wipe:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        if is_primary_group:
            user_remove(group)
        else:
            sudo("pw groupdel %s" % group)

    elif not is_primary_group:
        if len(members_of_group):
            for user in members:
                group_user_del(group, user)
        sudo("pw groupdel %s" % group)

