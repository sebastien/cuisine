import unittest, os, hashlib
import cuisine

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

class Modes(unittest.TestCase):

	def testModeLocal( self ):
		# We switch to remote and switch back to local
		assert cuisine.mode(cuisine.MODE_LOCAL)
		cuisine.mode_remote()
		assert not cuisine.mode(cuisine.MODE_LOCAL)
		cuisine.mode_local()
		assert cuisine.mode(cuisine.MODE_LOCAL)
		# We use the mode changer to switch to sudo temporarily
		with cuisine.mode_remote():
			assert not cuisine.mode(cuisine.MODE_LOCAL)
		assert cuisine.mode(cuisine.MODE_LOCAL)
		# We go into local from local
		with cuisine.mode_local():
			assert cuisine.mode(cuisine.MODE_LOCAL)

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
