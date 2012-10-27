# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Project   : Cuisine - Functions to write Fabric recipes
# -----------------------------------------------------------------------------
# Author    : Sebastien Pierre                            <sebastien@ffctn.com>
# Author    : Thierry Stiegler   (gentoo port)     <thierry.stiegler@gmail.com>
# Author    : Jim McCoy (distro checks and rpm port)      <jim.mccoy@gmail.com>
# Author    : Warren Moore (zypper package)               <warren@wamonite.com>
# License   : Revised BSD License
# -----------------------------------------------------------------------------
# Creation  : 26-Apr-2010
# Last mod  : 20-Sep-2012
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

:copyright: (c) 2011,2012 by Sébastien Pierre.
:license:   BSD, see LICENSE for more details.
"""

from __future__ import with_statement
import base64, bz2, hashlib, os, re, string, tempfile, subprocess, types, functools, StringIO
import fabric, fabric.api, fabric.operations, fabric.context_managers

VERSION         = "0.4.2"
RE_SPACES       = re.compile("[\s\t]+")
MAC_EOL         = "\n"
UNIX_EOL        = "\n"
WINDOWS_EOL     = "\r\n"
MODE_LOCAL      = "CUISINE_MODE_LOCAL"
MODE_SUDO       = "CUISINE_MODE_SUDO"
SUDO_PASSWORD   = "CUISINE_SUDO_PASSWORD"
OPTION_PACKAGE  = "CUISINE_OPTION_PACKAGE"
OPTION_PYTHON_PACKAGE  = "CUISINE_OPTION_PYTHON_PACKAGE"
AVAILABLE_OPTIONS = dict(
	package=["apt", "yum", "zypper"],
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
		self.oldMode = fabric.api.env.get(self.MODE_KEY)
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
	"""Selects the type of package subsystem to use (ex:apt, yum or zypper)."""
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
	process  = subprocess.Popen(command, shell=shell, stdout=subprocess.PIPE, stderr=stderr)
	out, err = process.communicate()
	# FIXME: Should stream the output, and only print it if fabric's properties allow it
	# print out
	# Wrap stdout string and add extra status attributes
	result = fabric.operations._AttributeString(out.rstrip('\n'))
	result.return_code = process.returncode
	result.succeeded   = process.returncode == 0
	result.failed      = not result.succeeded
	result.stderr      = StringIO.StringIO(err)
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

def sudo(*args, **kwargs):
	"""A wrapper to Fabric's run/sudo commands, using the
	'cuisine.MODE_SUDO' global to tell whether the command should be run as
	regular user or sudo."""
	with mode_sudo():
		return run(*args, **kwargs)

# =============================================================================
#
# DECORATORS
#
# =============================================================================

def dispatch(prefix=None):
	"""Dispatches the current function to specific implementation. The `prefix`
	parameter indicates the common option prefix, and the `option_select()`
	function will determine the function suffix.

	For instance the package functions are defined like that:

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
	cuisine.option_select("package", "yum")
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

def file_read(location):
	"""Reads the *remote* file at the given location."""
	# NOTE: We use base64 here to be sure to preserve the encoding (UNIX/DOC/MAC) of EOLs
	return base64.b64decode(run('cat "%s" | base64' % (location)))

def file_exists(location):
	"""Tests if there is a *remote* file at the given location."""
	return run('test -e "%s" && echo OK ; true' % (location)).endswith("OK")

def file_is_file(location):
	return run("test -f '%s' && echo OK ; true" % (location)).endswith("OK")

def file_is_dir(location):
	return run("test -d '%s' && echo OK ; true" % (location)).endswith("OK")

def file_is_link(location):
	return run("test -L '%s' && echo OK ; true" % (location)).endswith("OK")

def file_attribs(location, mode=None, owner=None, group=None, recursive=False):
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

def file_write(location, content, mode=None, owner=None, group=None, sudo=None, check=True):
	"""Writes the given content to the file at the given remote
	location, optionally setting mode/owner/group."""
	# FIXME: Big files are never transferred properly!
	# Gets the content signature and write it to a secure tempfile
	use_sudo       = sudo if sudo is not None else is_sudo()
	sig            = hashlib.sha256(content).hexdigest()
	fd, local_path = tempfile.mkstemp()
	os.write(fd, content)
	# Upload the content if necessary
	if not file_exists(location) or sig != file_sha256(location):
		if is_local():
			with mode_sudo(use_sudo):
				run('cp "%s" "%s"'%(local_path,location))
		else:
			# FIXME: Put is not working properly, I often get stuff like:
			# Fatal error: sudo() encountered an error (return code 1) while executing 'mv "3dcf7213c3032c812769e7f355e657b2df06b687" "/etc/authbind/byport/80"'
			#fabric.operations.put(local_path, location, use_sudo=use_sudo)
			# Hides the output, which is especially important
			with fabric.context_managers.settings(
				fabric.api.hide('warnings', 'running', 'stdout'),
				warn_only=True,
				**{MODE_SUDO: use_sudo}
			):
				# We send the data as BZipped Base64
				with mode_sudo(use_sudo):
					result = run("echo '%s' | base64 --decode | bzip2 --decompress > \"%s\"" % (base64.b64encode(bz2.compress(content)), location))
				if result.failed:
					fabric.api.abort('Encountered error writing the file %s: %s' % (location, result))

	# Remove the local temp file
	os.close(fd)
	os.unlink(local_path)
	# Ensures that the signature matches
	if check:
		with mode_sudo(use_sudo):
			file_sig = file_sha256(location)
		assert sig == file_sig, "File content does not matches file: %s, got %s, expects %s" % (location, repr(file_sig), repr(sig))
	with mode_sudo(use_sudo):
		file_attribs(location, mode=mode, owner=owner, group=group)

def file_ensure(location, mode=None, owner=None, group=None):
	"""Updates the mode/owner/group for the remote file at the given
	location."""
	if file_exists(location):
		file_attribs(location,mode=mode,owner=owner,group=group)
	else:
		file_write(location,"",mode=mode,owner=owner,group=group)

def file_upload(remote, local, sudo=None):
	"""Uploads the local file to the remote location only if the remote location does not
	exists or the content are different."""
	# FIXME: Big files are never transferred properly!
	use_sudo = is_sudo() or sudo #XXX: this 'sudo' kw arg shadows the function named 'sudo'
	f       = file(local, 'rb')
	content = f.read()
	f.close()
	sig     = hashlib.sha256(content).hexdigest()
	if not file_exists(remote) or sig != file_sha256(remote):
		if is_local():
			if use_sudo:
				sudo('cp "%s" "%s"'%(local,remote))
			else:
				run('cp "%s" "%s"'%(local,remote))
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
	run('echo "%s" | base64 -d > "%s"' % (base64.b64encode(new_content), location))

def file_append(location, content, mode=None, owner=None, group=None):
	"""Appends the given content to the remote file at the given
	location, optionally updating its mode/owner/group."""
	run('echo "%s" | base64 -d >> "%s"' % (base64.b64encode(content), location))
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

# =============================================================================
#
# DIRECTORY OPERATIONS
#
# =============================================================================

def dir_attribs(location, mode=None, owner=None, group=None, recursive=False):
	"""Updates the mode/owner/group for the given remote directory."""
	file_attribs(location, mode, owner, group, recursive)

def dir_exists(location):
	"""Tells if there is a remote directory at the given location."""
	return run('test -d "%s" && echo OK ; true' % (location)).endswith("OK")

def dir_ensure(location, recursive=False, mode=None, owner=None, group=None):
	"""Ensures that there is a remote directory at the given location,
	optionally updating its mode/owner/group.

	If we are not updating the owner/group then this can be done as a single
	ssh call, so use that method, otherwise set owner/group after creation."""
	if not dir_exists(location):
		run('mkdir %s "%s" && echo OK ; true' % (recursive and "-p" or "", location))
	if owner or group or mode:
		dir_attribs(location, owner=owner, group=group, mode=mode)

# =============================================================================
#
# PACKAGE OPERATIONS
#
# =============================================================================

@dispatch
def package_upgrade():
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

# -----------------------------------------------------------------------------
# APT PACKAGE (DEBIAN/UBUNTU)
# -----------------------------------------------------------------------------

def repository_ensure_apt(repository):
	sudo("add-apt-repository " + repository)

def package_update_apt(package=None):
	if package == None:
		sudo("apt-get --yes update")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo('DEBIAN_FRONTEND=noninteractive apt-get --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade ' + package)

def package_upgrade_apt():
	sudo('DEBIAN_FRONTEND=noninteractive apt-get --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade')

def package_install_apt(package, update=False):
	if update:
		sudo('DEBIAN_FRONTEND=noninteractive apt-get --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" update')
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("DEBIAN_FRONTEND=noninteractive apt-get --yes install %s" % (package))

def package_ensure_apt(package, update=False):
	status = run("dpkg-query -W -f='${Status}' %s ; true" % package)
	if status.find("not-installed") != -1 or status.find("installed") == -1:
		package_install(package, update)
		return False
	else:
		if update: package_update(package)
		return True

def package_clean_apt(package=None):
	pass

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
		package_install(package, update)
		return False
	else:
		if update: package_update(package)
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

def python_package_upgrade_pip(package,E=None):
	'''
	The "package" argument, defines the name of the package that will be upgraded.
	The optional argument "E" is equivalent to the "-E" parameter of pip. E is the
	path to a virtualenv. If provided, it will be added to the pip call.
	'''
	if E:
		E='-E %s' %E
	else:
		E=''   
	run('pip upgrade %s %s' %(E,package))

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

def python_package_ensure_pip(package=None,r=None, pip=None):
	'''
	The "package" argument, defines the name of the package that will be ensured.
	The argument "r" referes to the requirements file that will be used by pip and
	is equivalent to the "-r" parameter of pip.
	Either "package" or "r" needs to be provided
	The optional argument "E" is equivalent to the "-E" parameter of pip. E is the
	path to a virtualenv. If provided, it will be added to the pip call.
	'''
	#FIXME: At the moment, I do not know how to check for the existence of a pip package and
	# I am not sure if this really makes sense, based on the pip built in functionality. 
	# So I just call the install functions
	pip=pip or fabric.api.env.get('pip','pip')
	python_package_install_pip(package,r,pip)

def python_package_remove_pip(package, E=None, pip=None):
	'''
	The "package" argument, defines the name of the package that will be ensured.
	The argument "r" referes to the requirements file that will be used by pip and
	is equivalent to the "-r" parameter of pip.
	Either "package" or "r" needs to be provided
	The optional argument "E" is equivalent to the "-E" parameter of pip. E is the
	path to a virtualenv. If provided, it will be added to the pip call. 
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

def user_passwd(name, passwd, encrypted_passwd=False):
	"""Sets the given user password."""
	encoded_password = base64.b64encode("%s:%s" % (name, passwd))
	encryption = " -e" if encrypted_passwd else ""
	sudo("echo %s | base64 --decode | chpasswd%s" % (encoded_password, encryption))

def user_create(name, passwd=None, home=None, uid=None, gid=None, shell=None,
				uid_min=None, uid_max=None, encrypted_passwd=False):
	"""Creates the user with the given name, optionally giving a
	specific password/home/uid/gid/shell."""
	options = ["-m"]
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
	sudo("useradd %s '%s'" % (" ".join(options), name))
	if passwd:
		user_passwd(name,passwd,encrypted_passwd)

def user_check(name=None, uid=None):
	"""Checks if there is a user defined with the given name,
	returning its information as a
	'{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
	or 'None' if the user does not exists."""
	assert name!=None or uid!=None,     "user_check: either `uid` or `name` should be given"
	assert name is None or uid is None,"user_check: `uid` and `name` both given, only one should be provided"
	if   name != None:
		d = sudo("cat /etc/passwd | egrep '^%s:' ; true" % (name))
	elif uid != None:
		d = sudo("cat /etc/passwd | egrep '^.*:.*:%s:' ; true" % (uid))
	results = {}
	s = None
	if d:
		d = d.split(":")
		assert len(d) >= 7, "/etc/passwd entry is expected to have at least 7 fields, got %s in: %s" % (len(d), ":".join(d))
		results = dict(name=d[0], uid=d[2], gid=d[3], home=d[5], shell=d[6])
		s = sudo("cat /etc/shadow | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
		if s: results['passwd'] = s
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
		if passwd:
			user_passwd(name, passwd)

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

def group_user_del(group, user):
		"""remove the given user from the given group."""
		assert group_check(group), "Group does not exist: %s" % (group)
		if group_user_check(group, user):
				group_for_user = run("cat /etc/group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
				if group_for_user:
						sudo("usermod -G '%s' '%s'" % (",".join(group_for_user), user))

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
		return key_file
	else:
		return key_file

# =============================================================================
#
# MISC
#
# =============================================================================

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
		# Make sure that .ssh directory exists, see #42
		dir_ensure(os.path.dirname(keyf), owner=user, group=user, mode="700")
		file_write(keyf, key,             owner=user, group=user, mode="600")
		return False

def upstart_ensure(name):
	"""Ensures that the given upstart service is running, restarting
	it if necessary."""
	with fabric.api.settings(warn_only=True):
		status = sudo("service %s status" % name)
	if status.failed:
		sudo("service %s start" % name)
	else:
		sudo("service %s restart" % name)

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

#Only tested on Ubuntu!
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
