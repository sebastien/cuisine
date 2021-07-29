import os
from cuisine import *
import getpass
import tempfile
user = getpass.getuser()
path = tempfile.mkdtemp()
if not os.path.exists(path):
    os.mkdir(path)
cuisine.user_exists(user)
print("-- PREP test user does not exist")
assert not cuisine.user_exists("cuisine-demo"), "!! FAIL"
print(".. OK")
print("-- TEST Creating user")
cuisine.user_ensure("cuisine-demo", home=path, passwd="secret")
assert cuisine.user_exists("cuisine-demo"), "!! FAIL"
print(".. OK")
print("-- TEST Deleting user")
cuisine.user_remove("cuisine-demo", remove_home=True)
assert not cuisine.user_exists("cuisine-demo"), "!! FAIL"
print(".. OK")
# EOF
