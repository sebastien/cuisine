import unittest, os
import cuisine

def custom_run( cmd ):
	return os.popen(cmd).read()

class FileOperations(unittest.TestCase):

	def testB( self ):
		print cuisine.file_read("/etc/passwd")

	def testC( self ):
		pass

if __name__ == "__main__":
	# We bypass fabric as we want the tests to be run locally
	setattr(cuisine, "run",  custom_run)
	setattr(cuisine, "sudo", custom_run)
	unittest.main()

# EOF
