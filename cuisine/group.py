# -*- coding: utf-8 -*-
"""
    cuisine.group
    ~~~~~~~~~~~~~

    Helper functions for working with remote groups.

    :copyright: (c) 2011 by Sebastien Pierre, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

__all__ = ["create", "check", "ensure", "member", "add_user", "ensure_user"]

from fabric.api import sudo

from . import multiargs, run


def create(name, gid=None):
	"""Creates a group with the given name, and optionally given gid."""
	options = []
	if gid:  options.append("-g '%s'" % (gid))
	sudo("groupadd %s '%s'" % (" ".join(options), name))


def check(name):
	"""Checks if there is a group defined with the given name, returning its information
	as a '{"name":<str>,"gid":<str>,"members":<list[str]>}' or 'None' if the group
	does not exists."""
	group_data = run("cat /etc/group | egrep '^%s:' ; true" % (name))
	if group_data:
		name,_,gid,members = group_data.split(":",4)
		return dict(name=name,gid=gid,members=tuple(m.strip() for m in members.split(",")))
	else:
		return None


def ensure(name, gid=None):
	"""Ensures that the group with the given name (and optional gid) exists."""
	d = check(name)
	if not d:
		create(name, gid)
	else:
		if gid != None and d.get("gid") != gid:
			sudo("groupmod -g %s '%s'" % (gid, name))

def member(group, user):
	"""Checks if the given user is a member of the given group. It will return 'False'
	if the group does not exist."""
	d = check(group)
	if d is None:
		return False
	else:
		return user in d["members"]

@multiargs
def add_user(group, user):
	"""Adds the given user/list of users to the given group/groups."""
	from . import file

	assert check(group), "Group does not exist: %s" % (group)
	if not member(group, user):
		lines = []
		for line in file.read("/etc/group").split("\n"):
			if line.startswith(group + ":"):
				if line.strip().endswith(":"):
					line = line + user
				else:
					line = line + "," + user
			lines.append(line)
		text = "\n".join(lines)
		file.write("/etc/group", text)


def ensure_user(group, user):
	"""Ensure that a given user is a member of a given group."""
	d = check(group)
	if user not in d["members"]:
		add_user(group, user)
