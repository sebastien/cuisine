# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Project   : Cuisine - Functions to write Fabric recipes
# -----------------------------------------------------------------------------
# License   : Revised BSD License
# -----------------------------------------------------------------------------
# Authors   : Sebastien Pierre                            <sebastien@ffctn.com>
#             Thierry Stiegler   (gentoo port)     <thierry.stiegler@gmail.com>
#             Jim McCoy (distro checks and rpm port)      <jim.mccoy@gmail.com>
#             Warren Moore (zypper package)               <warren@wamonite.com>
#             Lorenzo Bivens (pkgin package)          <lorenzobivens@gmail.com>
# -----------------------------------------------------------------------------
# Creation  : 26-Apr-2010
# Last mod  : 05-Sep-2013
# -----------------------------------------------------------------------------

"""
`cuisine` makes it easy to write automatic server installation
and configuration recipes by wrapping common administrative tasks
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

:copyright: (c) 2011-2013 by Sébastien Pierre.
:license:   BSD, see LICENSE for more details.
"""

from __future__ import with_statement
import base64, hashlib, os, re, string, tempfile, subprocess, types
import tempfile, functools, StringIO
import fabric, fabric.api, fabric.operations, fabric.context_managers, fabric.state

VERSION               = "0.6.5"
RE_SPACES             = re.compile("[\s\t]+")
MAC_EOL               = "\n"
UNIX_EOL              = "\n"
WINDOWS_EOL           = "\r\n"
MODE_LOCAL            = "CUISINE_MODE_LOCAL"
MODE_SUDO             = "CUISINE_MODE_SUDO"
SUDO_PASSWORD         = "CUISINE_SUDO_PASSWORD"
OPTION_PACKAGE        = "CUISINE_OPTION_PACKAGE"
OPTION_PYTHON_PACKAGE = "CUISINE_OPTION_PYTHON_PACKAGE"
CMD_APT_GET           = 'DEBIAN_FRONTEND=noninteractive apt-get -q --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" '

AVAILABLE_OPTIONS = dict(
	package=["apt", "yum", "zypper", "pacman", "emerge", "pkgin"],
	python_package=["easy_install","pip"]
)

DEFAULT_OPTIONS = dict(
	package="apt",
	python_package="pip"
)

def sudo_password(password=None):
	"""Sets the password for the sudo command."""
	if password is None:
		return fabric.api.env.get(SUDO_PASSWORD)
	else:
		if not password:
			del fabric.api.env[SUDO_PASSWORD]
		else:
			fabric.api.env[SUDO_PASSWORD] = password

class __mode_switcher(object):
	"""A class that can be used to switch Cuisine's run modes by
	instanciating the class or using it as a context manager"""
	MODE_VALUE = True
	MODE_KEY   = None

	def __init__( self, value=None ):
		self.oldMode                  = fabric.api.env.get(self.MODE_KEY)
		fabric.api.env[self.MODE_KEY] = self.MODE_VALUE if value is None else value

	def __enter__(self):
		pass

	def __exit__(self, type, value, traceback):
		if self.oldMode is None:
			del fabric.api.env[self.MODE_KEY]
		else:
			fabric.api.env[self.MODE_KEY] = self.oldMode

class mode_local(__mode_switcher):
	"""Sets Cuisine into local mode, where run/sudo won't go through
	Fabric's API, but directly through a popen. This allows you to
	easily test your Cuisine scripts without using Fabric."""
	MODE_KEY   = MODE_LOCAL
	MODE_VALUE = True

class mode_remote(__mode_switcher):
	"""Comes back to Fabric's API for run/sudo. This basically reverts
	the effect of calling `mode_local()`."""
	MODE_KEY   = MODE_LOCAL
	MODE_VALUE = False

class mode_user(__mode_switcher):
	"""Cuisine functions will be executed as the current user."""
	MODE_KEY   = MODE_SUDO
	MODE_VALUE = False

class mode_sudo(__mode_switcher):
	"""Cuisine functions will be executed with sudo."""
	MODE_KEY   = MODE_SUDO
	MODE_VALUE = True

def mode(key):
	"""Queries the given Cuisine mode (ie. MODE_LOCAL, MODE_SUDO)"""
	return fabric.api.env.get(key, False)

def is_local():  return mode(MODE_LOCAL)
def is_remote(): return not mode(MODE_LOCAL)
def is_sudo():   return mode(MODE_SUDO)

# =============================================================================
#
# OPTIONS
#
# =============================================================================

def select_package( selection=None ):
	"""Selects the type of package subsystem to use (ex:apt, yum, zypper, pacman, or emerge)."""
	supported = AVAILABLE_OPTIONS["package"]
	if not (selection is None):
		assert selection in supported, "Option must be one of: %s"  % (supported)
		fabric.api.env[OPTION_PACKAGE] = selection
	return (fabric.api.env[OPTION_PACKAGE], supported)

def select_python_package( selection=None ):
	supported = AVAILABLE_OPTIONS["python_package"]
	if not (selection is None):
		assert selection in supported, "Option must be one of: %s"  % (supported)
		fabric.api.env[OPTION_PYTHON_PACKAGE] = selection
	return (fabric.api.env[OPTION_PYTHON_PACKAGE], supported)

# =============================================================================
#
# RUN/SUDO METHODS
#
# =============================================================================

def run_local(command, sudo=False, shell=True, pty=True, combine_stderr=None):
	"""
	Local implementation of fabric.api.run() using subprocess.

	Note: pty option exists for function signature compatibility and is
	ignored.
	"""
	if combine_stderr is None: combine_stderr = fabric.api.env.combine_stderr
	# TODO: Pass the SUDO_PASSWORD variable to the command here
	if sudo: command = "sudo " + command
	stderr   = subprocess.STDOUT if combine_stderr else subprocess.PIPE
	lcwd = fabric.state.env.get('lcwd', None) or None #sets lcwd to None if it bools to false as well
	process  = subprocess.Popen(command, shell=shell, stdout=subprocess.PIPE, stderr=stderr, cwd=lcwd)
	out, err = process.communicate()
	# FIXME: Should stream the output, and only print it if fabric's properties allow it
	# print out
	# SEE: http://docs.fabfile.org/en/1.7/api/core/operations.html#fabric.operations.run
	# Wrap stdout string and add extra status attributes
	result              = fabric.operations._AttributeString(out.rstrip('\n'))
	result.command      = command
	result.real_command = command
	result.return_code  = process.returncode
	result.succeeded    = process.returncode == 0
	result.failed       = not result.succeeded
	result.stderr       = StringIO.StringIO(err)
	return result

def run(*args, **kwargs):
	"""A wrapper to Fabric's run/sudo commands that takes into account
	the `MODE_LOCAL` and `MODE_SUDO` modes of Cuisine."""
	if is_local():
		if is_sudo():
			kwargs.setdefault("sudo", True)
		return run_local(*args, **kwargs)
	else:
		if is_sudo():
			return fabric.api.sudo(*args, **kwargs)
		else:
			return fabric.api.run(*args, **kwargs)

def cd(*args, **kwargs):
	"""A wrapper around Fabric's cd to change the local directory if
	mode is local"""
	if is_local():
		return fabric.api.lcd(*args, **kwargs)
	return fabric.api.cd(*args, **kwargs)


def sudo(*args, **kwargs):
	"""A wrapper to Fabric's run/sudo commands, using the
	'cuisine.MODE_SUDO' global to tell whether the command should be run as
	regular user or sudo."""
	with mode_sudo():
		return run(*args, **kwargs)

def connect( host, user="root"):
	"""Sets Fabric's current host to the given host. This is useful when
	using Cuisine in standalone."""
	# See http://docs.fabfile.org/en/1.3.2/usage/library.html
	fabric.api.env.host_string = host
	fabric.api.env.user        = user

# =============================================================================
#
# DECORATORS
#
# =============================================================================

def dispatch(prefix=None):
	"""Dispatches the current function to specific implementation. The `prefix`
	parameter indicates the common option prefix, and the `select_[option]()`
	function will determine the function suffix.

	For instance the package functions are defined like this:

	{{{
	@dispatch("package")
	def package_ensure(...):
		...
	def package_ensure_apt(...):
		...
	def package_ensure_yum(...):
		...
	}}}

	and then when a user does

	{{{
	cuisine.select_package("yum")
	cuisine.package_ensure(...)
	}}}

	then the `dispatch` function will dispatch `package_ensure` to
	`package_ensure_yum`.

	If your prefix is the first word of the function name before the
	first `_` then you can simply use `@dispatch` without parameters.
	"""
	def dispatch_wrapper(function, prefix=prefix):
		def wrapper(*args, **kwargs):
			function_name = function.__name__
			_prefix       = prefix or function_name.split("_")[0].replace(".","_")
			select        = fabric.api.env.get("CUISINE_OPTION_" + _prefix.upper())
			assert select, "No option defined for: %s, call select_%s(<YOUR OPTION>) to set it" % (_prefix.upper(), prefix.lower().replace(".","_"))
			function_name = function.__name__ + "_" + select
			specific      = eval(function_name)
			if specific:
				if type(specific) == types.FunctionType:
					return specific(*args, **kwargs)
				else:
					raise Exception("Function expected for: " + function_name)
			else:
				raise Exception("Function variant not defined: " + function_name)
		# We copy name and docstring
		functools.update_wrapper(wrapper, function)
		return wrapper
	if type(prefix) == types.FunctionType:
		return dispatch_wrapper(prefix, None)
	else:
		return dispatch_wrapper

# =============================================================================
#
# TEXT PROCESSING
#
# =============================================================================

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

def text_replace_line(text, old, new, find=lambda old, new: old == new, process=lambda _: _):
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
	if res[0] == '' and len(res) == 1:
		res = list()
	for line in lines:
		assert line.find(eol) == -1, "No EOL allowed in lines parameter: " + repr(line)
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

# =============================================================================
#
# FILE OPERATIONS
#
# =============================================================================

def file_local_read(location):
	"""Reads a *local* file from the given location, expanding '~' and
	shell variables."""
	p = os.path.expandvars(os.path.expanduser(location))
	f = file(p, 'rb')
	t = f.read()
	f.close()
	return t

def file_read(location, default=None):
	"""Reads the *remote* file at the given location, if default is not `None`,
	default will be returned if the file does not exist."""
	# NOTE: We use base64 here to be sure to preserve the encoding (UNIX/DOC/MAC) of EOLs
	if default is None:
		assert file_exists(location), "cuisine.file_read: file does not exists {0}".format(location)
	elif not file_exists(location):
		return default
	with fabric.context_managers.settings(
		fabric.api.hide('stdout')
	):
		frame = run('cat "%s" | openssl base64' % (location))
		return base64.b64decode(frame)

def file_exists(location):
	"""Tests if there is a *remote* file at the given location."""
	return run('test -e "%s" && echo OK ; true' % (location)).endswith("OK")

def file_is_file(location):
	return run("test -f '%s' && echo OK ; true" % (location)).endswith("OK")

def file_is_dir(location):
	return run("test -d '%s' && echo OK ; true" % (location)).endswith("OK")

def file_is_link(location):
	return run("test -L '%s' && echo OK ; true" % (location)).endswith("OK")

def file_attribs(location, mode=None, owner=None, group=None):
	"""Updates the mode/owner/group for the remote file at the given
	location."""
	return dir_attribs(location, mode, owner, group, False)

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

def file_write(location, content, mode=None, owner=None, group=None, sudo=None, check=True, scp=False):
	"""Writes the given content to the file at the given remote
	location, optionally setting mode/owner/group."""
	# FIXME: Big files are never transferred properly!
	# Gets the content signature and write it to a secure tempfile
	use_sudo       = sudo if sudo is not None else is_sudo()
	sig            = hashlib.md5(content).hexdigest()
	fd, local_path = tempfile.mkstemp()
	os.write(fd, content)
	# Upload the content if necessary
	if sig != file_md5(location):
		if is_local():
			with mode_sudo(use_sudo):
				run('cp "%s" "%s"'%(local_path,location))
		else:
			if scp:
				hostname = fabric.api.env.host_string if len(fabric.api.env.host_string.split(':')) == 1 else fabric.api.env.host_string.split(':')[0]
				scp_cmd = 'scp "%s" "%s"@"%s":"%s"'%(local_path,fabric.api.env.user,hostname,location)
				print('[localhost] ' +  scp_cmd)
				run_local(scp_cmd)
			else:
				# FIXME: Put is not working properly, I often get stuff like:
				# Fatal error: sudo() encountered an error (return code 1) while executing 'mv "3dcf7213c3032c812769e7f355e657b2df06b687" "/etc/authbind/byport/80"'
				#fabric.operations.put(local_path, location, use_sudo=use_sudo)
				# Hides the output, which is especially important
				with fabric.context_managers.settings(
					fabric.api.hide('stdout'),
					warn_only=True,
					**{MODE_SUDO: use_sudo}
				):
					# See: http://unix.stackexchange.com/questions/22834/how-to-uncompress-zlib-data-in-unix
					result = run("echo '%s' | openssl base64 -A -d -out \"%s\"" % (base64.b64encode(content), location))
					if "openssl:Error" in result:
						fabric.api.abort('cuisine.file_write("%s",...) failed because openssl does not support base64 command.' % (location))
	# Remove the local temp file
	os.fsync(fd)
	os.close(fd)
	os.unlink(local_path)
	# Ensures that the signature matches
	if check:
		with mode_sudo(use_sudo):
			file_sig = file_md5(location)
		assert sig == file_sig, "File content does not matches file: %s, got %s, expects %s" % (location, repr(file_sig), repr(sig))
	with mode_sudo(use_sudo):
		file_attribs(location, mode=mode, owner=owner, group=group)

def file_ensure(location, mode=None, owner=None, group=None, scp=False):
	"""Updates the mode/owner/group for the remote file at the given
	location."""
	if file_exists(location):
		file_attribs(location,mode=mode,owner=owner,group=group)
	else:
		file_write(location,"",mode=mode,owner=owner,group=group,scp=scp)

def file_upload(remote, local, sudo=None, scp=False):
	"""Uploads the local file to the remote location only if the remote location does not
	exists or the content are different."""
	# FIXME: Big files are never transferred properly!
	use_sudo = is_sudo() or sudo #XXX: this 'sudo' kw arg shadows the function named 'sudo'
	f       = file(local, 'rb')
	content = f.read()
	f.close()
	sig     = hashlib.md5(content).hexdigest()
	if not file_exists(remote) or sig != file_md5(remote):
		if is_local():
			if use_sudo:
				globals()['sudo']('cp "%s" "%s"'%(local,remote))
			else:
				run('cp "%s" "%s"'%(local,remote))
		else:
			if scp:
				hostname = fabric.api.env.host_string if len(fabric.api.env.host_string.split(':')) == 1 else fabric.api.env.host_string.split(':')[0]
				scp_cmd = 'scp "%s" "%s"@"%s":"%s"'%(local,fabric.api.env.user,hostname,remote)
				print('[localhost] ' +  scp_cmd)
				run_local(scp_cmd)
			else:
				fabric.operations.put(local, remote, use_sudo=use_sudo)

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
	# assert type(new_content) in (str, unicode, fabric.operations._AttributeString), "Updater must be like (string)->string, got: %s() = %s" %  (updater, type(new_content))
	run('echo "%s" | openssl base64 -A -d -out "%s"' % (base64.b64encode(new_content), location))

def file_append(location, content, mode=None, owner=None, group=None):
	"""Appends the given content to the remote file at the given
	location, optionally updating its mode/owner/group."""
	run('echo "%s" | openssl base64 -A -d >> "%s"' % (base64.b64encode(content), location))
	file_attribs(location, mode, owner, group)

def file_unlink(path):
	if file_exists(path):
		run("unlink '%s'" % (path))

def file_link(source, destination, symbolic=True, mode=None, owner=None, group=None):
	"""Creates a (symbolic) link between source and destination on the remote host,
	optionally setting its mode/owner/group."""
	if file_exists(destination) and (not file_is_link(destination)):
		raise Exception("Destination already exists and is not a link: %s" % (destination))
	# FIXME: Should resolve the link first before unlinking
	if file_is_link(destination):
		file_unlink(destination)
	if symbolic:
		run('ln -sf "%s" "%s"' % (source, destination))
	else:
		run('ln -f "%s" "%s"' % (source, destination))
	file_attribs(destination, mode, owner, group)

def file_sha256(location):
	"""Returns the SHA-256 sum (as a hex string) for the remote file at the given location."""
	# NOTE: In some cases, sudo can output errors in here -- but the errors will
	# appear before the result, so we simply split and get the last line to
	# be on the safe side.
	sig = run('shasum -a 256 "%s" | cut -d" " -f1' % (location)).split("\n")
	return sig[-1].strip()

def file_md5(location):
	"""Returns the MD5 sum (as a hex string) for the remote file at the given location."""
	# NOTE: In some cases, sudo can output errors in here -- but the errors will
	# appear before the result, so we simply split and get the last line to
	# be on the safe side.
	sig = run('md5sum "%s" | cut -d" " -f1' % (location)).split("\n")
	return sig[-1].strip()

# =============================================================================
#
# PROCESS OPERATIONS
#
# =============================================================================

def process_find(name, exact=False):
	"""Returns the pids of processes with the given name. If exact is `False`
	it will return the list of all processes that start with the given
	`name`."""
	is_string = isinstance(name,str) or isinstance(name,unicode)
	# NOTE: ps -A seems to be the only way to not have the grep appearing
	# as well
	if is_string: processes = run("ps -A | grep {0} ; true".format(name))
	else:         processes = run("ps -A")
	res = []
	for line in processes.split("\n"):
		if not line.strip(): continue
		line = RE_SPACES.split(line,3)
		# 3010 pts/1    00:00:07 gunicorn
		# PID  TTY      TIME     CMD
		# 0    1        2        3
		# We skip lines that are not like we expect them (sometimes error
		# message creep up the output)
		if len(line) < 4: continue
		pid, tty, time, command = line
		if is_string:
			if pid and ((exact and command == name) or (not exact and command.find(name) >= 0)):
				res.append(pid)
		elif name(line) and pid:
			res.append(pid)
	return res

def process_kill(name, signal=9, exact=False):
	"""Kills the given processes with the given name. If exact is `False`
	it will return the list of all processes that start with the given
	`name`."""
	for pid in process_find(name, exact):
		run("kill -s {0} {1} ; true".format(signal, pid))

# =============================================================================
#
# DIRECTORY OPERATIONS
#
# =============================================================================

def dir_attribs(location, mode=None, owner=None, group=None, recursive=False):
	"""Updates the mode/owner/group for the given remote directory."""
	recursive = recursive and "-R " or ""
	if mode:
		run('chmod %s %s "%s"' % (recursive, mode,  location))
	if owner:
		run('chown %s %s "%s"' % (recursive, owner, location))
	if group:
		run('chgrp %s %s "%s"' % (recursive, group, location))

def dir_exists(location):
	"""Tells if there is a remote directory at the given location."""
	return run('test -d "%s" && echo OK ; true' % (location)).endswith("OK")

def dir_remove(location, recursive=True):
	""" Removes a directory """
	flag = ''
	if recursive:
		flag = 'r'
	if dir_exists(location):
		return run('rm -%sf %s && echo OK ; true' % (flag, location))

def dir_ensure(location, recursive=False, mode=None, owner=None, group=None):
	"""Ensures that there is a remote directory at the given location,
	optionally updating its mode/owner/group.

	If we are not updating the owner/group then this can be done as a single
	ssh call, so use that method, otherwise set owner/group after creation."""
	if not dir_exists(location):
		run('mkdir %s "%s"' % (recursive and "-p" or "", location))
	if owner or group or mode:
		dir_attribs(location, owner=owner, group=group, mode=mode, recursive=recursive)

# =============================================================================
#
# PACKAGE OPERATIONS
#
# =============================================================================

@dispatch
def package_upgrade(distupgrade=False):
	"""Updates every package present on the system."""

@dispatch
def package_update(package=None):
	"""Updates the package database (when no argument) or update the package
	or list of packages given as argument."""

@dispatch
def package_install(package, update=False):
	"""Installs the given package/list of package, optionally updating
	the package database."""

@dispatch
def package_ensure(package, update=False):
	"""Tests if the given package is installed, and installs it in
	case it's not already there. If `update` is true, then the
	package will be updated if it already exists."""

@dispatch
def package_clean(package=None):
	"""Clean the repository for un-needed files."""

@dispatch
def package_remove(package, autoclean=False):
	"""Remove package and optionally clean unused packages"""

# -----------------------------------------------------------------------------
# APT PACKAGE (DEBIAN/UBUNTU)
# -----------------------------------------------------------------------------

def repository_ensure_apt(repository):
	package_ensure_apt('python-software-properties')
	sudo("add-apt-repository --yes " + repository)

def apt_get(cmd):
	cmd    = CMD_APT_GET + cmd
	result = sudo(cmd)
	# If the installation process was interrupted, we might get the following message
	# E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a' to correct the problem.
	if "sudo dpkg --configure -a" in result:
		sudo("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
	return sudo(cmd)

def package_update_apt(package=None):
	if package == None:
		return apt_get("-q --yes update")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		return apt_get(' upgrade ' + package)

def package_upgrade_apt(distupgrade=False):
	if distupgrade:
		return apt_get("dist-upgrade")
	else:
		return apt_get("upgrade")

def package_install_apt(package, update=False):
	if update: apt_get("update")
	if type(package) in (list, tuple):
		package = " ".join(package)
	return apt_get("install " + package)

def package_ensure_apt(package, update=False):
	"""Ensure apt packages are installed"""
	if isinstance(package, basestring):
		package = package.split()
	res = {}
	for p in package:
		p = p.strip()
		if not p: continue
		# The most reliable way to detect success is to use the command status
		# and suffix it with OK. This won't break with other locales.
		status = run("dpkg-query -W -f='${Status} ' %s && echo OK;true" % p)
		if not status.endswith("OK") or "not-installed" in status:
			package_install_apt(p)
			res[p]=False
		else:
			if update:
				package_update_apt(p)
			res[p]=True
	if len(res) == 1:
		return res.values()[0]
	else:
		return res

def package_clean_apt(package=None):
	if type(package) in (list, tuple):
		package = " ".join(package)
	return apt_get("-y --purge remove %s" % package)

def package_remove_apt(package, autoclean=False):
	apt_get('remove ' + package)
	if autoclean:
		apt_get("autoclean")

# -----------------------------------------------------------------------------
# YUM PACKAGE (RedHat, CentOS)
# added by Prune - 20120408 - v1.0
# -----------------------------------------------------------------------------

def repository_ensure_yum(repository):
	raise Exception("Not implemented for Yum")

def package_upgrade_yum():
	sudo("yum -y update")

def package_update_yum(package=None):
	if package == None:
		sudo("yum -y update")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo("yum -y upgrade " + package)

def package_install_yum(package, update=False):
	if update:
		sudo("yum -y update")
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("yum -y install %s" % (package))

def package_ensure_yum(package, update=False):
	status = run("yum list installed %s ; true" % package)
	if status.find("No matching Packages") != -1 or status.find(package) == -1:
		package_install_yum(package, update)
		return False
	else:
		if update: package_update_yum(package)
		return True

def package_clean_yum(package=None):
	sudo("yum -y clean all")

# -----------------------------------------------------------------------------
# ZYPPER PACKAGE (openSUSE)
# -----------------------------------------------------------------------------

def repository_ensure_zypper(repository):
	repository_uri = repository
	if repository[-1] != '/':
		repository_uri = repository.rpartition("/")[0]
	status = run("zypper --non-interactive --gpg-auto-import-keys repos -d")
	if status.find(repository_uri) == -1:
		sudo("zypper --non-interactive --gpg-auto-import-keys addrepo " + repository)
		sudo("zypper --non-interactive --gpg-auto-import-keys modifyrepo --refresh " + repository_uri)

def package_upgrade_zypper():
	sudo("zypper --non-interactive --gpg-auto-import-keys update --type package")

def package_update_zypper(package=None):
	if package == None:
		sudo("zypper --non-interactive --gpg-auto-import-keys refresh")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo("zypper --non-interactive --gpg-auto-import-keys update --type package " + package)

def package_install_zypper(package, update=False):
	if update:
		package_update_zypper()
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("zypper --non-interactive --gpg-auto-import-keys install --type package --name " + package)

def package_ensure_zypper(package, update=False):
	status = run("zypper --non-interactive --gpg-auto-import-keys search --type package --installed-only --match-exact %s ; true" % package)
	if status.find("No packages found.") != -1 or status.find(package) == -1:
		package_install_zypper(package)
		return False
	else:
		if update:
			package_update_zypper(package)
		return True

def package_clean_zypper():
	sudo("zypper --non-interactive clean")

# -----------------------------------------------------------------------------
# PACMAN PACKAGE (Arch)
# -----------------------------------------------------------------------------

def repository_ensure_pacman(repository):
	raise Exception("Not implemented for Pacman")

def package_update_pacman(package=None):
	if package == None:
		sudo("pacman --noconfirm -Sy")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo("pacman --noconfirm -S " + package)

def package_upgrade_pacman():
	sudo("pacman --noconfirm -Syu")

def package_install_pacman(package, update=False):
	if update:
		sudo("pacman --noconfirm -Sy")
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("pacman --noconfirm -S %s" % (package))

def package_ensure_pacman(package, update=False):
	"""Ensure apt packages are installed"""
	if not isinstance(package, basestring):
		package = " ".join(package)
	status = run("pacman -Q %s ; true" % package)
	if ('was not found' in status):
		package_install_pacman(package, update)
		return False
	else:
		if update:
			package_update_pacman(package)
		return True

def package_clean_pacman():
	sudo("pacman --noconfirm -Sc")

def package_remove_pacman(package, autoclean=False):
	if autoclean:
		sudo('pacman --noconfirm -Rs ' + package)
	else:
		sudo('pacman --noconfirm -R ' + package)


# -----------------------------------------------------------------------------
# EMERGE PACKAGE (Gentoo Portage)
# added by davidmmiller - 20130417 - v0.1 (status - works for me...)
# -----------------------------------------------------------------------------

def repository_ensure_emerge(repository):
	raise Exception("Not implemented for emerge")
	"""This will be used to add Portage overlays in a future update."""

def package_upgrade_emerge(distupgrade=False):
		sudo("emerge -q --update --deep --newuse --with-bdeps=y world")

def package_update_emerge(package=None):
	if package == None:
		sudo("emerge -q --sync")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo("emerge -q --update --newuse %s" % package)

def package_install_emerge(package, update=False):
	if update:
		sudo("emerge -q --sync")
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("emerge -q %s" % (package))

def package_ensure_emerge(package, update=False):
	if not isinstance(package, basestring):
		package = " ".join(package)
	if update:
		sudo("emerge -q --update --newuse %s" % package)
	else:
		sudo("emerge -q --noreplace %s" % package)

def package_clean_emerge(package=None):
	if type(package) in (list, tuple):
		package = " ".join(package)
	if package:
		sudo("CONFIG_PROTECT='-*' emerge --quiet-unmerge-warn --unmerge %s" % package)
	else:
		sudo('emerge -q --depclean')
		sudo('revdep-rebuild -q')

def package_remove_emerge(package, autoclean=False):
	if autoclean:
		sudo('emerge --quiet-unmerge-warn --unmerge ' + package)
		sudo('emerge -q --depclean')
		sudo('revdep-rebuild -q')
	else:
		sudo('emerge --quiet-unmerge-warn --unmerge ' + package)

# -----------------------------------------------------------------------------
# PKGIN (Illumos, SmartOS, BSD, OSX)
# added by lbivens - 20130520 - v0.5 (this works but can be better)
# -----------------------------------------------------------------------------

# This should be simple but I have to think it properly
def repository_ensure_pkgin(repository):
	raise Exception("Not implemented for pkgin")

def package_upgrade_pkgin():
	sudo("pkgin -y upgrade")

def package_update_pkgin(package=None):
	#test if this works
	if package == None:
		sudo("pkgin -y update")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo("pkgin -y upgrade " + package)

def package_install_pkgin(package, update=False):
	if update:
		sudo("pkgin -y update")
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("pkgin -y install %s" % (package))

def package_ensure_pkgin(package, update=False):
	# I am gonna have to do something different here
	status = run("pkgin list | grep %s ; true" % package)
	if status.find("No matching Packages") != -1 or status.find(package) == -1:
		package_install(package, update)
		return False
	else:
		if update: package_update(package)
		return True

def package_clean_pkgin(package=None):
	sudo("pkgin -y clean")

# =============================================================================
#
# PYTHON PACKAGE OPERATIONS
#
# =============================================================================

@dispatch('python_package')
def python_package_upgrade(package):
	'''
	Upgrades the defined python package.
	'''

@dispatch('python_package')
def python_package_install(package=None):
	'''
	Installs the given python package/list of python packages.
	'''

@dispatch('python_package')
def python_package_ensure(package):
	'''
	Tests if the given python package is installed, and installes it in
	case it's not already there.
	'''

@dispatch('python_package')
def python_package_remove(package):
	'''
	Removes the given python package.
	'''

# -----------------------------------------------------------------------------
# PIP PYTHON PACKAGE MANAGER
# -----------------------------------------------------------------------------

def python_package_upgrade_pip(package):
	'''
	The "package" argument, defines the name of the package that will be upgraded.
	'''
	run('pip install --upgrade %s' %(package))

def python_package_install_pip(package=None,r=None,pip=None):
	'''
	The "package" argument, defines the name of the package that will be installed.
	The argument "r" referes to the requirements file that will be used by pip and
	is equivalent to the "-r" parameter of pip.
	Either "package" or "r" needs to be provided
	The optional argument "E" is equivalent to the "-E" parameter of pip. E is the
	path to a virtualenv. If provided, it will be added to the pip call.
	'''
	pip=pip or fabric.api.env.get('pip','pip')
	if package:
		run('%s install %s' %(pip,package))
	elif r:
		run('%s install -r %s' %(pip,r))
	else:
		raise Exception("Either a package name or the requirements file has to be provided.")

def python_package_ensure_pip(package=None, r=None, pip=None):
	'''
	The "package" argument, defines the name of the package that will be ensured.
	The argument "r" referes to the requirements file that will be used by pip and
	is equivalent to the "-r" parameter of pip.
	Either "package" or "r" needs to be provided
	'''
	#FIXME: At the moment, I do not know how to check for the existence of a pip package and
	# I am not sure if this really makes sense, based on the pip built in functionality.
	# So I just call the install functions
	pip=pip or fabric.api.env.get('pip','pip')
	python_package_install_pip(package,r,pip)

def python_package_remove_pip(package, pip=None):
	'''
	The "package" argument, defines the name of the package that will be ensured.
	The argument "r" referes to the requirements file that will be used by pip and
	is equivalent to the "-r" parameter of pip.
	Either "package" or "r" needs to be provided
	'''
	pip=pip or fabric.api.env.get('pip','pip')
	return run('%s uninstall %s' %(pip,package))

# -----------------------------------------------------------------------------
# EASY_INSTALL PYTHON PACKAGE MANAGER
# -----------------------------------------------------------------------------

def python_package_upgrade_easy_install(package):
	'''
	The "package" argument, defines the name of the package that will be upgraded.
	'''
	run('easy_install --upgrade %s' %package)

def python_package_install_easy_install(package):
	'''
	The "package" argument, defines the name of the package that will be installed.
	'''
	sudo('easy_install %s' %package)

def python_package_ensure_easy_install(package):
	'''
	The "package" argument, defines the name of the package that will be ensured.
	'''
	#FIXME: At the moment, I do not know how to check for the existence of a py package and
	# I am not sure if this really makes sense, based on the easy_install built in functionality.
	# So I just call the install functions
	python_package_install_easy_install(package)

def python_package_remove_easy_install(package):
	'''
	The "package" argument, defines the name of the package that will be removed.
	'''
	#FIXME: this will not remove egg file etc.
	run('easy_install -m %s' %package)

# =============================================================================
#
# SHELL COMMANDS
#
# =============================================================================

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

# =============================================================================
#
# USER OPERATIONS
#
# =============================================================================

def user_passwd(name, passwd, encrypted_passwd=True):
	"""Sets the given user password. Password is expected to be encrypted by default."""
	encoded_password = base64.b64encode("%s:%s" % (name, passwd))
	if encrypted_passwd:
		sudo("usermod -p '%s' %s" % (passwd,name))
	else:
		# NOTE: We use base64 here in case the password contains special chars
		sudo("echo %s | openssl base64 -A -d | chpasswd" % (encoded_password))

def user_create(name, passwd=None, home=None, uid=None, gid=None, shell=None,
	uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
	"""Creates the user with the given name, optionally giving a
	specific password/home/uid/gid/shell."""
	options = []

	if home:
		options.append("-d '%s'" % (home))
	if uid:
		options.append("-u '%s'" % (uid))
	#if group exists already but is not specified, useradd fails
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
		user_passwd(name=name,passwd=passwd,encrypted_passwd=encrypted_passwd)

def user_check(name=None, uid=None, need_passwd=True):
	"""Checks if there is a user defined with the given name,
	returning its information as a
	'{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
	or 'None' if the user does not exists.
	need_passwd (Boolean) indicates if password to be included in result or not.
		If set to True it parses 'getent shadow' and needs sudo access
	"""
	assert name!=None or uid!=None,     "user_check: either `uid` or `name` should be given"
	assert name is None or uid is None,"user_check: `uid` and `name` both given, only one should be provided"
	if   name != None:
		d = run("getent passwd | egrep '^%s:' ; true" % (name))
	elif uid != None:
		d = run("getent passwd | egrep '^.*:.*:%s:' ; true" % (uid))
	results = {}
	s = None
	if d:
		d = d.split(":")
		assert len(d) >= 7, "passwd entry returned by getent is expected to have at least 7 fields, got %s in: %s" % (len(d), ":".join(d))
		results = dict(name=d[0], uid=d[2], gid=d[3], fullname=d[4], home=d[5], shell=d[6])
		if need_passwd:
			s = sudo("getent shadow | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
			if s: results['passwd'] = s
	if results:
		return results
	else:
		return None

def user_ensure(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
	"""Ensures that the given users exists, optionally updating their
	passwd/home/uid/gid/shell."""
	d = user_check(name)
	if not d:
		user_create(name, passwd, home, uid, gid, shell, fullname=fullname, encrypted_passwd=encrypted_passwd)
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
			user_passwd(name=name, passwd=passwd, encrypted_passwd=encrypted_passwd)

def user_remove(name, rmhome=None):
	"""Removes the user with the given name, optionally
	removing the home directory and mail spool."""
	options = ["-f"]
	if rmhome:
		options.append("-r")
	sudo("userdel %s '%s'" % (" ".join(options), name))

# =============================================================================
#
# GROUP OPERATIONS
#
# =============================================================================

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
	group_data = run("getent group | egrep '^%s:' ; true" % (name))
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

def group_user_del(group, user):
		"""remove the given user from the given group."""
		assert group_check(group), "Group does not exist: %s" % (group)
		if group_user_check(group, user):
				group_for_user = run("getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
				if group_for_user:
						sudo("usermod -G '%s' '%s'" % (",".join(group_for_user), user))
				else:
						sudo("usermod -G '' '%s'" % (user))

def group_remove(group=None, wipe=False):
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
# SSH
#
# =============================================================================

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
		return key_file
	else:
		return key_file

def ssh_authorize(user, key):
	"""Adds the given key to the '.ssh/authorized_keys' for the given
	user."""
	d = user_check(user, need_passwd=False)
	group = d["gid"]
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
		# Make sure that .ssh directory exists, see #42
		dir_ensure(os.path.dirname(keyf), owner=user, group=group, mode="700")
		file_write(keyf, key,             owner=user, group=group, mode="600")
		return False

def ssh_unauthorize(user, key):
	"""Removes the given key to the '.ssh/authorized_keys' for the given
	user."""
	d = user_check(user, need_passwd=False)
	group = d["gid"]
	keyf = d["home"] + "/.ssh/authorized_keys"
	if file_exists(keyf):
		tmpfile = tempfile.NamedTemporaryFile()
		fabric.operations.get(keyf, tmpfile.name)
		keys = [line.strip() for line in tmpfile]
		tmpfile.close()
		if key in keys:
			tmpfile = tempfile.NamedTemporaryFile()
			keys.remove(key)
			content = '\n'.join(keys) + '\n'
			tmpfile.write(content)
			tmpfile.flush()
			fabric.operations.put(tmpfile.name, keyf, mode=0600)
			tmpfile.close()
	return True

# =============================================================================
#
# UPSTART
#
# =============================================================================

def upstart_ensure(name):
	"""Ensures that the given upstart service is running, starting
	it if necessary."""
	with fabric.api.settings(warn_only=True):
		status = sudo("service %s status" % name)
	if status.failed:
		sudo("service %s start" % name)


def upstart_stop(name):
	"""Ensures that the given upstart service is stopped."""
	with fabric.api.settings(warn_only=True):
		status = sudo("service %s status" % name)
	if status.succeeded:
		sudo("service %s stop" % name)


# =============================================================================
#
# SYSTEM
#
# =============================================================================

def system_uuid_alias_add():
	"""Adds system UUID alias to /etc/hosts.
	Some tools/processes rely/want the hostname as an alias in
	/etc/hosts e.g. `127.0.0.1 localhost <hostname>`.
	"""
	with mode_sudo():
		old = "127.0.0.1 localhost"
		new = old + " " + system_uuid()
		file_update('/etc/hosts', lambda x: text_replace_line(x, old, new)[0])

def system_uuid():
	"""Gets a machines UUID (Universally Unique Identifier)."""
	return sudo('dmidecode -s system-uuid | tr "[A-Z]" "[a-z]"')

# =============================================================================
#
# LOCALE
#
# =============================================================================


def locale_check(locale):
	locale_data = sudo("locale -a | egrep '^%s$' ; true" % (locale,))
	return locale_data == locale

def locale_ensure(locale):
	if not locale_check(locale):
		with fabric.context_managers.settings(warn_only=True):
			sudo("/usr/share/locales/install-language-pack %s" % (locale,))
		sudo("dpkg-reconfigure locales")

# Sets up the default options so that @dispatch'ed functions work
def _init():
	for option, value in DEFAULT_OPTIONS.items():
		eval("select_" + option)(value)

_init()

# EOF - vim: ts=4 sw=4 noet
