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
# Last mod  : 18-May-2016
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
import base64, hashlib, os, re, string, tempfile, subprocess, types, threading, sys
import tempfile, functools, StringIO
import fabric, fabric.api, fabric.operations, fabric.context_managers, fabric.state, fabric.version
import platform

try:
	# NOTE: Reporter is a custom module that follows the logging interface
	# but provides more backends and options.
	import reporter
	reporter.StdoutReporter.Install()
	reporter.setLevel(reporter.TRACE)
	logging = reporter.bind("cuisine")
except ImportError:
	import logging

if not (fabric.version.VERSION[0] > 1 or fabric.version.VERSION[1] >= 7):
	sys.stderr.write("[!] Cuisine requires Fabric 1.7+")

VERSION                 = "0.7.12"
NOTHING                 = base64
RE_SPACES               = re.compile("[\s\t]+")
STRINGIFY_MAXSTRING     = 80
STRINGIFY_MAXLISTSTRING = 20
MAC_EOL                 = "\n"
UNIX_EOL                = "\n"
WINDOWS_EOL             = "\r\n"
MODE_LOCAL              = "CUISINE_MODE_LOCAL"
MODE_SUDO               = "CUISINE_MODE_SUDO"
SUDO_PASSWORD           = "CUISINE_SUDO_PASSWORD"
OPTION_PACKAGE          = "CUISINE_OPTION_PACKAGE"
OPTION_PYTHON_PACKAGE   = "CUISINE_OPTION_PYTHON_PACKAGE"
OPTION_OS_FLAVOUR       = "CUISINE_OPTION_OS_FLAVOUR"
OPTION_USER             = "CUISINE_OPTION_USER"
OPTION_GROUP            = "CUISINE_OPTION_GROUP"
OPTION_HASH             = "CUISINE_OPTION_HASH"
CMD_APT_GET             = 'DEBIAN_FRONTEND=noninteractive apt-get -q --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" '
SHELL_ESCAPE            = " '\";`|"
STATS                   = None

AVAILABLE_OPTIONS = dict(
	package        = ["apt", "yum", "zypper", "pacman", "emerge", "pkgin", "pkgng"],
	python_package = ["easy_install","pip"],
	os_flavour     = ["linux",  "bsd"],
	user           = ["linux",  "bsd"],
	group          = ["linux",  "bsd"],
	hash           = ["python", "openssl"]
)

DEFAULT_OPTIONS = dict(
	package        = "apt",
	python_package = "pip",
	os_flavour     = "linux",
	user           = "linux",
	group          = "linux",
	hash           = "python"
)

# logging.info("Welcome to Cuisine v{0}".format(VERSION))

# =============================================================================
#
# STATS
#
# =============================================================================

class Stats(object):
	"""A work-in-progress class to store cuisine's statistics, so that you
	can have a summary of what has been done."""

	def __init__( self ):
		self.filesRead         = []
		self.filesWritten      = []
		self.packagesInstalled = []

# =============================================================================
#
# DECORATORS
#
# =============================================================================

def stringify( value ):
	"""Turns the given value in a user-friendly string that can be displayed"""
	if   type(value) in (str, unicode, bytes) and len(value) > STRINGIFY_MAXSTRING:
		return "{0}...".format(value[0:STRINGIFY_MAXSTRING])
	elif type(value) in (list, tuple) and len(value) > 10:
		return"[{0},...]".format(", ".join([stringify(_) for _ in value[0:STRINGIFY_MAXLISTSTRING]]))
	else:
		return str(value)

def log_message( message ):
	"""Logs the given message"""
	logging.info( message )

def log_error( message ):
	"""Logs the given error message"""
	logging.error( message )

def log_call( function, args, kwargs ):
	"""Logs the given function call"""
	function_name = function.__name__
	a = ", ".join([stringify(_) for _ in args] + [str(k) + "=" + stringify(v) for k,v in kwargs.items()])
	logging.debug("{0}({1})".format(function_name, a))

def logged(message=None):
	"""Logs the invoked function name and arguments."""
	# TODO: Options - prevent sub @logged to output anything
	# TODO: Message - allow to specify a message
	# TODO: Category - read/write/exec as well as mode
	# [2013-10-28T10:18:32] user@host [sudo|user] [R/W] cuinine.function(xx,xxx,xx) [time]
	# [2013-10-28T10:18:32] user@host [sudo|user] [!] Exception
	def logged_wrapper(function, message=message):
		def wrapper(*args, **kwargs):
			log_call(function, args, kwargs)
			return function(*args, **kwargs)
		# We copy name and docstring
		functools.update_wrapper(wrapper, function)
		return wrapper
	if type(message) == types.FunctionType:
		return logged_wrapper(message, None)
	else:
		return logged_wrapper

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
# MODES
#
# =============================================================================

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

def shell_safe( path ):
	"""Makes sure that the given path/string is escaped and safe for shell"""
	return "".join([("\\" + _) if _ in SHELL_ESCAPE else _ for _ in path])

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

def select_user( selection=None ):
	supported = AVAILABLE_OPTIONS["user"]
	if not (selection is None):
		assert selection in supported, "Option must be one of: %s"  % (supported)
		fabric.api.env[OPTION_USER] = selection
	return (fabric.api.env[OPTION_USER], supported)

def select_group( selection=None ):
	supported = AVAILABLE_OPTIONS["group"]
	if not (selection is None):
		assert selection in supported, "Option must be one of: %s"  % (supported)
		fabric.api.env[OPTION_GROUP] = selection
	return (fabric.api.env[OPTION_GROUP], supported)

def select_os_flavour( selection=None ):
	supported = AVAILABLE_OPTIONS["os_flavour"]
	if not (selection is None):
		assert selection in supported, "Option must be one of: %s"  % (supported)
		fabric.api.env[OPTION_OS_FLAVOUR] = selection
		# select the correct implementation for user,group management
		# either useradd,groupadd for linux, or pw user/pw group for BSD
		select_user(selection)
		select_group(selection)
	return (fabric.api.env[OPTION_OS_FLAVOUR], supported)

def select_hash( selection=None ):
	supported = AVAILABLE_OPTIONS["hash"]
	if not (selection is None):
		assert selection in supported, "Option must be one of: %s"  % (supported)
		fabric.api.env[OPTION_HASH] = selection
	return (fabric.api.env[OPTION_HASH], supported)

def options():
	"""Retrieves the list of options as a dictionary."""
	return {k:fabric.api.env[k] for k in (
		OPTION_PACKAGE,
		OPTION_PYTHON_PACKAGE,
		OPTION_OS_FLAVOUR,
		OPTION_USER,
		OPTION_GROUP,
		OPTION_HASH)}

def is_ok( text ):
	"""Tells if the given text ends with "OK", swallowing trailing blanks."""
	while text and text[-1] in "\r\n\t ":
		text = text[:-1]
	return text.endswith("OK")

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
	logging.debug("run_local: {0} in {1}".format(command, lcwd or "."))
	process  = subprocess.Popen(command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=lcwd)
	# NOTE: This is not ideal, but works well.
	# See http://stackoverflow.com/questions/15654163/how-to-capture-streaming-output-in-python-from-subprocess-communicate
	# At some point, we should use a single thread.
	out = []
	err = []
	# FIXME: This does not seem to stream
	def stdout_reader():
		for line in process.stdout:
			if line: logging.debug(line.rstrip("\n").rstrip("\r"))
			out.append(line)
	def stderr_reader():
		for line in process.stderr:
			logging.error(line.rstrip("\n").rstrip("\r"))
			err.append(line)
	t0 = threading.Thread(target=stdout_reader)
	t1 = threading.Thread(target=stderr_reader)
	t0.start()
	t1.start()
	process.wait()
	t0.join()
	t1.join()
	out = "".join(out)
	err = "".join(err)
	# SEE: http://docs.fabfile.org/en/1.7/api/core/operations.html#fabric.operations.run
	# Wrap stdout string and add extra status attributes
	# SEE: fabric.operations._run_command. for the code below
	out = fabric.operations._AttributeString(out.rstrip('\n'))
	err = fabric.operations._AttributeString(err.rstrip('\n'))
	# Error handling
	status           = process.returncode
	out.failed       = False
	out.command      = command
	out.real_command = command
	if status not in fabric.state.env.ok_ret_codes:
		out.failed = True
		msg = "run_local received nonzero return code %s while executing" % (status)
		if fabric.state.env.warn_only:
			msg += " '%s'!" % command
		else:
			msg += "!\nExecuted: %s" % (command)
		logging.debug(msg)
		for _ in err.split("\n"):logging.error(_)
		fabric.utils.error(message=msg, stdout=out, stderr=err)
	# Attach return code to output string so users who have set things to
	# warn only, can inspect the error code.
	out.return_code = status
	# Convenience mirror of .failed
	out.succeeded = not out.failed
	# Attach stderr for anyone interested in that.
	out.stderr = err
	return out

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

def pwd():
	"""Returns the current directory."""
	# FIXME: Might not work with Fabric's lpwd
	return run("pwd")

@logged
def sudo(*args, **kwargs):
	"""A wrapper to Fabric's run/sudo commands, using the
	'cuisine.MODE_SUDO' global to tell whether the command should be run as
	regular user or sudo."""
	with mode_sudo():
		return run(*args, **kwargs)

def disconnect(host=None):
	"""Disconnects the current connction, if any."""
	host = host or fabric.api.env.host_string
	if host and host in fabric.state.connections:
		fabric.state.connections[host].get_transport().close()
@logged
def connect( host, user="root", password=NOTHING):
	"""Sets Fabric's current host to the given host. This is useful when
	using Cuisine in standalone."""
	disconnect()
	# See http://docs.fabfile.org/en/1.3.2/usage/library.html
	fabric.api.env.host_string = host
	fabric.api.env.user        = user
	if password is not NOTHING:
		fabric.api.env.password = password


def host( name=NOTHING ):
	"""Returns or sets the host"""
	if name is not NOTHING:
		fabric.api.env.host_string = name
	return fabric.api.env.host_string

def user( name=NOTHING ):
	"""Returns or sets the user"""
	if name is not NOTHING:
		fabric.api.env.user = name
	return fabric.api.env.user

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
	text and the count of replacements.

	Returns: (text, number of lines replaced)

	`process` is a function that will pre-process each line (you can think of
	it as a normalization function, by default it will return the string as-is),
	and `find` is the function that will compare the current line to the
	`old` line.

	The finds the line using `find(process(current_line), process(old_line))`,
	and if this matches, will insert the new line instead.
	"""
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

def text_replace_regex(text, regex, new, **kwargs):
	"""Replace lines that match with the regex returning the new text

	Returns: text

	`kwargs` is for the compatibility with re.sub(),
	then we can use flags=re.IGNORECASE there for example.
	"""
	res = []
	eol = text_detect_eol(text)
	for line in text.split(eol):
		res.append(re.sub(regex, new, line, **kwargs))
	return eol.join(res)

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
	"""Will strip all the characters before the left margin identified
	by the `margin` character in your text. For instance

	```
			|Hello, world!
	```

	will result in

	```
	Hello, world!
	```
	"""
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

@logged
def file_local_read(location):
	"""Reads a *local* file from the given location, expanding '~' and
	shell variables."""
	p = os.path.expandvars(os.path.expanduser(location))
	f = file(p, 'rb')
	t = f.read()
	f.close()
	return t


@logged
def file_backup(location, suffix=".orig", once=False):
	"""Backups the file at the given location in the same directory, appending
	the given suffix. If `once` is True, then the backup will be skipped if
	there is already a backup file."""
	backup_location = location + suffix
	if once and file_exists(backup_location):
		return False
	else:
		return run("cp -a {0} {1}".format(
			shell_safe(location),
			shell_safe(backup_location)
		))

@logged
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
		frame = file_base64(location)
		return base64.b64decode(frame)

def file_exists(location):
	"""Tests if there is a *remote* file at the given location."""
	return is_ok(run('test -e %s && echo OK ; true' % (shell_safe(location))))

def file_is_file(location):
	return is_ok(run("test -f %s && echo OK ; true" % (shell_safe(location))))

def file_is_dir(location):
	return is_ok(run("test -d %s && echo OK ; true" % (shell_safe(location))))

def file_is_link(location):
	return is_ok(run("test -L %s && echo OK ; true" % (shell_safe(location))))

@logged
def file_attribs(location, mode=None, owner=None, group=None):
	"""Updates the mode/owner/group for the remote file at the given
	location."""
	return dir_attribs(location, mode, owner, group, False)

@logged
def file_attribs_get(location):
	"""Return mode, owner, and group for remote path.
	Return mode, owner, and group if remote path exists, 'None'
	otherwise.
	"""
	if file_exists(location):
		fs_check = run('stat %s %s' % (shell_safe(location), '--format="%a %U %G"'))
		(mode, owner, group) = fs_check.split(' ')
		return {'mode': mode, 'owner': owner, 'group': group}
	else:
		return None

@logged
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
				run('cp %s %s'%(shell_safe(local_path), shell_safe(location)))
		else:
			if scp:
				hostname = fabric.api.env.host_string if len(fabric.api.env.host_string.split(':')) == 1 else fabric.api.env.host_string.split(':')[0]
				scp_cmd = 'scp %s %s@%s:%s'% (shell_safe(local_path), shell_safe(fabric.api.env.user), shell_safe(hostname), shell_safe(location))
				logging.debug('file_write:[localhost]] ' +  scp_cmd)
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
					# SEE: http://unix.stackexchange.com/questions/22834/how-to-uncompress-zlib-data-in-unix
					# TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
					result = run("echo '%s' | openssl base64 -A -d -out %s" % (base64.b64encode(content), shell_safe(location)))
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

@logged
def file_ensure(location, mode=None, owner=None, group=None, scp=False):
	"""Updates the mode/owner/group for the remote file at the given
	location."""
	if file_exists(location):
		file_attribs(location,mode=mode,owner=owner,group=group)
	else:
		file_write(location,"",mode=mode,owner=owner,group=group,scp=scp)

@logged
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
				globals()['sudo']('cp %s %s'%(shell_safe(local), shell_safe(remote)))
			else:
				run('cp "%s" "%s"'%(local,remote))
		else:
			if scp:
				hostname = fabric.api.env.host_string if len(fabric.api.env.host_string.split(':')) == 1 else fabric.api.env.host_string.split(':')[0]
				scp_cmd = 'scp %s %s@%s:%s'%( shell_safe(local), shell_safe(fabric.api.env.user), shell_safe(hostname), shell_safe(remote))
				logging.debug('file_upload():[localhost] ' +  scp_cmd)
				run_local(scp_cmd)
			else:
				fabric.operations.put(local, remote, use_sudo=use_sudo)

@logged
def file_update(location, updater=lambda x: x):
	"""Updates the content of the given by passing the existing
	content of the remote file at the given location to the 'updater'
	function. Return true if file content was changed.

	For instance, if you'd like to convert an existing file to all
	uppercase, simply do:

	>   file_update("/etc/myfile", lambda _:_.upper())

	Or restart service on config change:

	>   if file_update("/etc/myfile.cfg", lambda _: text_ensure_line(_, line)): run("service restart")
	"""
	assert file_exists(location), "File does not exists: " + location
	old_content = file_read(location)
	new_content = updater(old_content)
	if (old_content == new_content):
		return False
	# assert type(new_content) in (str, unicode, fabric.operations._AttributeString), "Updater must be like (string)->string, got: %s() = %s" %  (updater, type(new_content))
	file_write(location, new_content)
	return True

@logged
def file_append(location, content, mode=None, owner=None, group=None):
	"""Appends the given content to the remote file at the given
	location, optionally updating its mode/owner/group."""
	# TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
	run('echo "%s" | openssl base64 -A -d >> %s' % (base64.b64encode(content), shell_safe(location)))
	file_attribs(location, mode, owner, group)

@logged
def file_unlink(path):
	if file_exists(path):
		run("unlink %s" % (shell_safe(path)))

@logged
def file_link(source, destination, symbolic=True, mode=None, owner=None, group=None):
	"""Creates a (symbolic) link between source and destination on the remote host,
	optionally setting its mode/owner/group."""
	if file_exists(destination) and (not file_is_link(destination)):
		raise Exception("Destination already exists and is not a link: %s" % (destination))
	# FIXME: Should resolve the link first before unlinking
	if file_is_link(destination):
		file_unlink(destination)
	if symbolic:
		run('ln -sf %s %s' % (shell_safe(source), shell_safe(destination)))
	else:
		run('ln -f %s %s' % (shell_safe(source), shell_safe(destination)))
	file_attribs(destination, mode, owner, group)

# SHA256/MD5 sums with openssl are tricky to get working cross-platform
# SEE: https://github.com/sebastien/cuisine/pull/184#issuecomment-102336443
# SEE: http://stackoverflow.com/questions/22982673/is-there-any-function-to-get-the-md5sum-value-of-file-in-linux

@logged
def file_base64(location):
	"""Returns the base64-encoded content of the file at the given location."""
	if fabric.api.env[OPTION_HASH] == "python":
		return run("cat {0} | python -c 'import sys,base64;sys.stdout.write(base64.b64encode(sys.stdin.read()))'".format(shell_safe((location))))
	else:
		return run("cat {0} | openssl base64".format(shell_safe((location))))

@logged
def file_sha256(location):
	"""Returns the SHA-256 sum (as a hex string) for the remote file at the given location."""
	# NOTE: In some cases, sudo can output errors in here -- but the errors will
	# appear before the result, so we simply split and get the last line to
	# be on the safe side.
	if fabric.api.env[OPTION_HASH] == "python":
		if file_exists(location):
			return run("cat {0} | python -c 'import sys,hashlib;sys.stdout.write(hashlib.sha256(sys.stdin.read()).hexdigest())'".format(shell_safe((location))))
		else:
			return None
	else:
		return run('openssl dgst -sha256 %s' % (shell_safe(location))).split("\n")[-1].split(")= ",1)[-1].strip()

@logged
def file_md5(location):
	"""Returns the MD5 sum (as a hex string) for the remote file at the given location."""
	# NOTE: In some cases, sudo can output errors in here -- but the errors will
	# appear before the result, so we simply split and get the last line to
	# be on the safe side.
	if fabric.api.env[OPTION_HASH] == "python":
		if file_exists(location):
			return run("cat {0} | python -c 'import sys,hashlib;sys.stdout.write(hashlib.md5(sys.stdin.read()).hexdigest())'".format(shell_safe((location))))
		else:
			return None
	else:
		return run('openssl dgst -md5 %s' % (shell_safe(location))).split("\n")[-1].split(")= ",1)[-1].strip()

# =============================================================================
#
# PROCESS OPERATIONS
#
# =============================================================================

@logged
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

@logged
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

@logged
def dir_attribs(location, mode=None, owner=None, group=None, recursive=False):
	"""Updates the mode/owner/group for the given remote directory."""
	recursive = recursive and "-R " or ""
	if mode:
		run('chmod %s %s %s' % (recursive, mode,  shell_safe(location)))
	if owner:
		run('chown %s %s %s' % (recursive, owner, shell_safe(location)))
	if group:
		run('chgrp %s %s %s' % (recursive, group, shell_safe(location)))

def dir_exists(location):
	"""Tells if there is a remote directory at the given location."""
	return run('test -d %s && echo OK ; true' % (shell_safe(location))).endswith("OK")

@logged
def dir_remove(location, recursive=True):
	""" Removes a directory """
	flag = ''
	if recursive:
		flag = 'r'
	if dir_exists(location):
		return run('rm -%sf %s && echo OK ; true' % (flag, shell_safe(location)))

def dir_ensure(location, recursive=False, mode=None, owner=None, group=None):
	"""Ensures that there is a remote directory at the given location,
	optionally updating its mode/owner/group.

	If we are not updating the owner/group then this can be done as a single
	ssh call, so use that method, otherwise set owner/group after creation."""
	if not dir_exists(location):
		run('mkdir %s %s' % (recursive and "-p" or "", shell_safe(location)))
	if owner or group or mode:
		dir_attribs(location, owner=owner, group=group, mode=mode, recursive=recursive)

# =============================================================================
#
# PACKAGE OPERATIONS
#
# =============================================================================

@logged
@dispatch
def package_upgrade(distupgrade=False):
	"""Updates every package present on the system."""

@logged
@dispatch
def package_update(package=None):
	"""Updates the package database (when no argument) or update the package
	or list of packages given as argument."""

@logged
@dispatch
def package_install(package, update=False):
	"""Installs the given package/list of package, optionally updating
	the package database."""

@logged
@dispatch
def package_ensure(package, update=False):
	"""Tests if the given package is installed, and installs it in
	case it's not already there. If `update` is true, then the
	package will be updated if it already exists."""

@logged
@dispatch
def package_clean(package=None):
	"""Clean the repository for un-needed files."""

@logged
@dispatch
def package_remove(package, autoclean=False):
	"""Remove package and optionally clean unused packages"""

# -----------------------------------------------------------------------------
# APT PACKAGE (DEBIAN/UBUNTU)
# -----------------------------------------------------------------------------

@logged
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
		result = sudo(cmd)
	return result

def package_update_apt(package=None):
	if package == None:
		return apt_get("-q --yes update")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		return apt_get(' install --only-upgrade ' + package)

def package_upgrade_apt(distupgrade=False):
	if distupgrade:
		return apt_get("dist-upgrade")
	else:
		return apt_get("install --only-upgrade")

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

def package_remove_yum(package, autoclean=False):
	sudo("yum -y remove %s" % (package))

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

def package_remove_zypper(package, autoclean=False):
	sudo("zypper --non-interactive remove %s" % (package))

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


# -----------------------------------------------------------------------------
# PKG - FreeBSD
# -----------------------------------------------------------------------------

def repository_ensure_pkgng(repository):
	raise Exception("Not implemented for pkgng")

def package_upgrade_pkgng():
	sudo("echo y | pkg upgrade")

def package_update_pkgng(package=None):
	#test if this works
	if package == None:
		sudo("pkg -y update")
	else:
		if type(package) in (list, tuple):
			package = " ".join(package)
		sudo("pkg upgrade " + package)

def package_install_pkgng(package, update=False):
	if update:
		sudo("pkg update")
	if type(package) in (list, tuple):
		package = " ".join(package)
	sudo("echo y | pkg install %s" % (package))

def package_ensure_pkgng(package, update=False):
	# I am gonna have to do something different here
	status = run("pkg info %s ; true" % package)
	if status.stderr.find("No package(s) matching") != -1 or status.find(package) == -1:
		package_install_pkgng(package, update)
		return False
	else:
		if update: package_update_pkgng(package)
		return True

def package_clean_pkgng(package=None):
	sudo("pkg delete %s" % (package))

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

def python_package_upgrade_pip(package, pip=None):
	'''
	The "package" argument, defines the name of the package that will be upgraded.
	'''
	pip=pip or fabric.api.env.get('pip','pip')
	run('%s install --upgrade %s' % (pip, package))

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
		sudo("usermod -p '%s' %s" % (passwd,name))
	else:
		# NOTE: We use base64 here in case the password contains special chars
		# TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
		sudo("echo %s | openssl base64 -A -d | chpasswd" % (shell_safe(encoded_password)))

def user_create_linux(name, passwd=None, home=None, uid=None, gid=None, shell=None,
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

def user_create_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
	uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
	"""Creates the user with the given name, optionally giving a
	specific password/home/uid/gid/shell."""
	options = []

	if home:
		options.append("-d '%s'" % (home))
	if uid:
		options.append("-u %s" % (uid))
	#if group exists already but is not specified, useradd fails
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
		user_passwd(name=name,passwd=passwd,encrypted_passwd=encrypted_passwd)

def user_check_linux(name=None, uid=None, need_passwd=True):
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

def user_ensure_linux(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
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
		sudo("echo %s | openssl base64 -A -d | chpasswd" % (shell_safe(encoded_password)))

def user_create_passwd_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
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

def user_create_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None,
	uid_min=None, uid_max=None, encrypted_passwd=True, fullname=None, createhome=True):
	"""Creates the user with the given name, optionally giving a
	specific password/home/uid/gid/shell."""
	options = []

	if home:
		options.append("-d '%s'" % (home))
	if uid:
		options.append("-u %s" % (uid))
	#if group exists already but is not specified, useradd fails
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
		user_passwd(name=name,passwd=passwd,encrypted_passwd=encrypted_passwd)

def user_check_bsd(name=None, uid=None, need_passwd=True):
	"""Checks if there is a user defined with the given name,
	returning its information as a
	'{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
	or 'None' if the user does not exists.
	need_passwd (Boolean) indicates if password to be included in result or not.
		If set to True it parses 'getent passwd' and needs sudo access
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
			s = sudo("getent passwd | egrep '^%s:' | awk -F':' '{print $2}'" % (results['name']))
			if s: results['passwd'] = s
	if results:
		return results
	else:
		return None

def user_ensure_bsd(name, passwd=None, home=None, uid=None, gid=None, shell=None, fullname=None, encrypted_passwd=True):
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
			sudo("pw usermod %s '%s'" % (name, " ".join(options)))
		if passwd:
			user_passwd(name=name, passwd=passwd, encrypted_passwd=encrypted_passwd)

def user_remove_bsd(name, rmhome=None):
	"""Removes the user with the given name, optionally
	removing the home directory and mail spool."""
	options = ["-f"]
	if rmhome:
		options.append("-r")
	sudo("pw userdel %s '%s'" % (" ".join(options), name))

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
				group_for_user = run("getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
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
			group_for_user = run("getent group | egrep -v '^%s:' | grep '%s' | awk -F':' '{print $1}' | grep -v %s; true" % (group, user, user)).splitlines()
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
	d     = user_check(user, need_passwd=False)
	group = d["gid"]
	keyf  = d["home"] + "/.ssh/authorized_keys"
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
	"""Removes the given key to the remote '.ssh/authorized_keys' for the given
	user."""
	key   = key.strip()
	d     = user_check(user, need_passwd=False)
	group = d["gid"]
	keyf  = d["home"] + "/.ssh/authorized_keys"
	if file_exists(keyf):
		file_write(keyf, "\n".join(_ for _ in file_read(keyf).split("\n") if _.strip() != key), owner=user, group=group, mode="600")
		return True
	else:
		return False

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
		status = sudo("service %s start" % name)
	return status

def upstart_reload(name):
	"""Reloads the given service, or starts it if it is not running."""
	with fabric.api.settings(warn_only=True):
		status = sudo("service %s reload" % name)
	if status.failed:
		status = sudo("service %s start" % name)
	return status

def upstart_restart(name):
	"""Tries a `restart` command to the given service, if not successful
	will stop it and start it. If the service is not started, will start it."""
	with fabric.api.settings(warn_only=True):
		status = sudo("service %s status" % name)
	if status.failed:
		return sudo("service %s start" % name)
	else:
		status = sudo("service %s restart" % name)
		if status.failed:
			sudo("service %s stop"  % name)
			return sudo("service %s start" % name)
		else:
			return status

def upstart_stop(name):
	"""Ensures that the given upstart service is stopped."""
	with fabric.api.settings(warn_only=True):
		status = sudo("service %s status" % name)
	if status.succeeded:
		status = sudo("service %s stop" % name)
	return status


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
# RSYNC
#
# =============================================================================

def rsync(local_path, remote_path, compress=True, progress=False, verbose=True, owner=None, group=None):
	"""Rsyncs local to remote, using the connection's host and user."""
	options = "-a"
	if compress: options += "z"
	if verbose:  options += "v"
	if progress: options += " --progress"
	if owner or group:
		assert owner and group or not owner
		options += " --chown={0}{1}".format(owner or "", ":" + group if group else "")
	with mode_local():
		run("rsync {options} {local} {user}@{host}:{remote}".format(
			options = options,
			host    = host(),
			user    = user(),
			local   = local_path,
			remote  = remote_path,
		))

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
	STATS = Stats()
	# NOTE: Removed from now as is seems to cause problems #188
	# # If we don't find a host, we setup the local mode
	# if not fabric.api.env.host_string: mode_local()
	# We set the default options
	for option, value in DEFAULT_OPTIONS.items(): eval("select_" + option)(value)

_init()

# EOF - vim: ts=4 sw=4 noet
