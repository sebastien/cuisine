import unittest, os, hashlib, shutil
import cuisine
import tempfile
import fabric.api
from fabric.api import env, settings, cd

USER = os.popen("whoami").read()[:-1]

class Text(unittest.TestCase):

	def testEnsureLine( self ):
		some_text = "foo"
		some_text = cuisine.text_ensure_line(some_text, "bar")
		assert some_text == 'foo\nbar'
		some_text = cuisine.text_ensure_line(some_text, "bar")
		assert some_text == 'foo\nbar'

class Users(unittest.TestCase):

	def testUserCheck( self ):
		user_data = cuisine.user_check(USER)
		assert user_data
		assert user_data["name"] == USER
		assert user_data == cuisine.user_check(name=USER)
		# We ensure that user_check works with uid and name
		assert cuisine.user_check(uid=user_data["uid"])
		assert cuisine.user_check(uid=user_data["uid"])["name"] == user_data["name"]

class Modes(unittest.TestCase):

	def testModeLocal( self ):
		# We switch to remote and switch back to local
		assert cuisine.mode(cuisine.MODE_LOCAL)
		cuisine.mode_remote()
		assert not cuisine.mode(cuisine.MODE_LOCAL)
		cuisine.mode_local()
		assert cuisine.mode(cuisine.MODE_LOCAL)
		# We use the mode changer to switch to remote temporarily
		with cuisine.mode_remote():
			assert not cuisine.mode(cuisine.MODE_LOCAL)
		assert cuisine.mode(cuisine.MODE_LOCAL)
		# We go into local from local
		with cuisine.mode_local():
			assert cuisine.mode(cuisine.MODE_LOCAL)

	def testModeSudo( self ):
		assert not cuisine.mode(cuisine.MODE_SUDO)
		cuisine.mode_sudo()
		assert cuisine.mode(cuisine.MODE_SUDO)
		cuisine.mode_user()
		assert not cuisine.mode(cuisine.MODE_SUDO)
		# We use the mode changer to switch to sudo temporarily
		with cuisine.mode_sudo():
			assert cuisine.mode(cuisine.MODE_SUDO)
		assert cuisine.mode(cuisine.MODE_LOCAL)
		# We go into sudo from sudo
		with cuisine.mode_sudo():
			assert cuisine.mode(cuisine.MODE_SUDO)


# NOTE: Test disabled for now
# 	def testSudoApplication( self ):
# 		tmpdir = tempfile.mkdtemp()
# 		try:
# 			with cd(tmpdir), cuisine.mode_sudo():
# 				cuisine.run('echo "test" > test.txt')
# 				cuisine.run('chmod 0600 test.txt')
# 
# 			with cd(tmpdir), cuisine.mode_user(), settings(warn_only=True):
# 				listing = cuisine.run('ls -la test.txt').split()
# 				self.assertEqual('root', listing[2])  # user
# 				self.assertEqual('root', listing[3])  # group
# 				result = cuisine.run('cat test.txt')
# 				self.assertTrue(result.failed)
# 				self.assertIn('Permission denied', result)
# 		finally:
# 			shutil.rmtree(tmpdir)

# NOTE: Test disabled for now
# class LocalExecution(unittest.TestCase):
# 
# 	def testFabricLocalCommands( self ):
# 		'''
# 		Make sure local and lcd still work properly and that run and cd
# 		in local mode don't interfere.
# 		'''
# 		tmpdir = tempfile.mkdtemp()
# 		try:
# 			dir1 = os.path.join(tmpdir, 'test1')
# 			dir2 = os.path.join(tmpdir, 'test2')
# 			[os.mkdir(d) for d in [dir1, dir2]]
# 			
# 			with cd(dir1), fabric.api.lcd(dir2):
# 				file1 = os.path.join(dir1, 'test1.txt')
# 				cuisine.run('touch %s' % file1)
# 
# 				file2 = os.path.join(dir2, 'test2.txt')
# 				fabric.api.local('touch %s' % file2)
# 
# 				self.assertTrue(cuisine.file_exists(file2))
# 		finally:
# 			shutil.rmtree(tmpdir)
# 
# 
# 	def testResultAttributes( self ):
# 		failing_command = 'cat /etc/shadow'	# insufficient permissions
# 		succeeding_command = 'uname -a'
# 		erroneous_command = 'this-command-does-not-exist -a'
# 
# 		# A successful command should have the appropriate status
# 		# attributes set
# 		result = cuisine.run(succeeding_command)
# 		self.assertTrue(result.succeeded)
# 		self.assertFalse(result.failed)
# 		self.assertEqual(result.return_code, 0)
# 
# 		# With warn_only set, we should be able to examine the result
# 		# even if it fails
# 		with settings(warn_only=True):
# 			# command should fail with output to stderr
# 			result = cuisine.run(failing_command, combine_stderr=False)
# 			self.assertTrue(result.failed)
# 			self.assertFalse(result.succeeded)
# 			self.assertEqual(result.return_code, 1)
# 			self.assertIsNotNone(result.stderr)
# 			self.assertIn('Permission denied', result.stderr)
# 
# 		# With warn_only off, failure should cause execution to abort
# 		with settings(warn_only=False):
# 			with self.assertRaises(SystemExit):
# 				cuisine.run(failing_command)
# 
# 		# An erroneoneous command should fail similarly to fabric
# 		with settings(warn_only=True):
# 			result = cuisine.run(erroneous_command)
# 			self.assertTrue(result.failed)
# 			self.assertEqual(result.return_code, 127)
# 
# 	def testCd( self ):
# 		with cd('/tmp'):
# 			self.assertEqual(cuisine.run('pwd'), '/tmp')
# 
# 	def testShell( self ):
# 		# Ensure that env.shell is respected by setting it to the 
# 		# 'exit' command and testing that it aborts.
# 		with settings(use_shell=True, shell='exit'):
# 			with self.assertRaises(SystemExit):
# 				cuisine.run('ls')
# 
# 	def testSudoPrefix( self ):
# 		# Ensure that env.sudo_prefix is respected by setting it to
# 		# echo the command to stdout rather than executing it
# 		with settings(use_shell=True, sudo_prefix="echo %s"):
# 			cmd = 'ls -la'
# 			run_result = cuisine.run(cmd)
# 			sudo_result = cuisine.sudo(cmd)
# 			self.assertNotEqual(run_result.stdout, sudo_result.stdout)
# 			self.assertIn(env.shell, sudo_result)
# 			self.assertIn(cmd, sudo_result)
# 
# 	def testPath( self ):
# 		# Make sure the path is applied properly by setting it empty 
# 		# and making sure that stops a simple command from running
# 		self.assertTrue(cuisine.run('ls').succeeded)
# 
# 		with fabric.api.path(' ', behavior='replace'), settings(warn_only=True):
# 			result = cuisine.run('ls', combine_stderr=False)
# 			self.assertTrue(result.failed)
# 			self.assertIn("command not found", result.stderr)


class Files(unittest.TestCase):

	def testRead( self ):
		cuisine.file_read("/etc/passwd")

	def testWrite( self ):
		content = "Hello World!"
		path    = "/tmp/cuisine.test"
		cuisine.file_write(path, content, check=False)
		assert os.path.exists(path)
		with file(path) as f:
			assert f.read() == content
		os.unlink(path)

	def testSHA1( self ):
		content = "Hello World!"
		path    = "/tmp/cuisine.test"
		cuisine.file_write(path, content, check=False)
		sig = cuisine.file_sha256(path)
		with file(path) as f:
			file_sig = hashlib.sha256(f.read()).hexdigest()
		assert sig == file_sig

	def testExists( self ):
		try:
			fd, path = tempfile.mkstemp()
			f = os.fdopen(fd, 'w')
			f.write('Hello World!')
			f.close()
			assert cuisine.file_exists(path)
		finally:
			os.unlink(path)


class Packages(unittest.TestCase):

	def testInstall( self ):
		pass
		#with cuisine.mode_sudo():
		#	cuisine.package_ensure("tmux")

class SSHKeys(unittest.TestCase):

	def testKeygen( self ):
		pass
		# if cuisine.ssh_keygen(USER):
		# 	print "SSH keys already there"
		# else:
		# 	print "SSH keys created"

	def testAuthorize( self ):
		key = "ssh-dss XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX= user@cuisine"""
		cuisine.ssh_authorize(USER, key)
		# FIXME: Should check that the key is present, and only one

if __name__ == "__main__":
	# We bypass fabric as we want the tests to be run locally
	cuisine.mode_local()
	unittest.main()

# EOF
