import unittest, os
import cuisine

USER = os.popen("whoami").read()[:-1]

def custom_run( cmd ):
	if cuisine.MODE == "sudo":
		return os.popen(cmd).read()[:-1]
	else:
		return os.popen("sudo " + cmd).read()[:-1]

def custom_sudo( cmd ):
	return os.popen("sudo " + cmd).read()[:-1]

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
		print "USER_DATA", user_data

class Files(unittest.TestCase):

	def testB( self ):
		cuisine.file_read("/etc/passwd")

	def testC( self ):
		pass

class Packages(unittest.TestCase):

	def testInstall( self ):
		pass
		#with cuisine.mode_sudo():
		#	cuisine.package_ensure("tmux")

class SSHKeys(unittest.TestCase):

	def testKeygen( self ):
		if cuisine.ssh_keygen(USER):
			print "SSH keys already there"
		else:
			print "SSH keys created"

	def testAuthorize( self ):
		key = "ssh-dss XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX= user@cuisine"""
		cuisine.ssh_authorize(USER, key)
		# FIXME: Should check that the key is present, and only one

if __name__ == "__main__":
	# We bypass fabric as we want the tests to be run locally
	setattr(cuisine, "run",  custom_run)
	setattr(cuisine, "sudo", custom_sudo)
	unittest.main()

# EOF
