import unittest, os
import cuisine

def custom_run( cmd ):
	if cuisine.MODE == "sudo":
		return os.popen(cmd).read()
	else:
		return os.popen("sudo " + cmd).read()

def custom_sudo( cmd ):
	return os.popen("sudo " + cmd).read()

class FileOperations(unittest.TestCase):

	def testB( self ):
		print cuisine.file_read("/etc/passwd")

	def testC( self ):
		pass

class PakcageOperations(unittest.TestCase):

	def testInstall( self ):
		with cuisine.mode_sudo():
			cuisine.package_ensure("tmux")

if __name__ == "__main__":
	# We bypass fabric as we want the tests to be run locally
	setattr(cuisine, "run",  custom_run)
	setattr(cuisine, "sudo", custom_sudo)
	unittest.main()

# EOF
