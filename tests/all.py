import unittest
import os
import hashlib
import tempfile
import sys

USER = os.popen("whoami").read()[:-1]
sys.path.insert(0, 'src/')
import cuisine


class Text(unittest.TestCase):

    def testEnsureLine(self):
        some_text = "foo"
        some_text = cuisine.text_ensure_line(some_text, "bar")
        assert some_text == 'foo\nbar'
        some_text = cuisine.text_ensure_line(some_text, "bar")
        assert some_text == 'foo\nbar'


class Users(unittest.TestCase):

    def testUserCheck(self):
        user_data = cuisine.user_check(USER)
        assert user_data
        assert user_data["name"] == USER
        assert user_data == cuisine.user_check(name=USER)
        # We ensure that user_check works with uid and name
        assert cuisine.user_check(uid=user_data["uid"])
        assert cuisine.user_check(uid=user_data["uid"])["name"] == user_data["name"]

    def testUserCheckNeedPasswd(self):
        user_data = cuisine.user_check(USER, need_passwd=False)
        user_data_with_passwd = cuisine.user_check(name=USER)
        assert user_data
        assert user_data["name"] == USER
        assert 'passwd' in user_data_with_passwd
        assert 'passwd' not in user_data
        # We ensure that user_check works with uid and name
        assert cuisine.user_check(uid=user_data["uid"], need_passwd=False)
        assert cuisine.user_check(uid=user_data["uid"], need_passwd=False)["name"] == user_data["name"]


class Modes(unittest.TestCase):

    def testModeLocal(self):
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

    def testModeSudo(self):
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
#       def testSudoApplication(self):
#               tmpdir = tempfile.mkdtemp()
#               try:
#                       with cd(tmpdir), cuisine.mode_sudo():
#                               cuisine.run('echo "test" > test.txt')
#                               cuisine.run('chmod 0600 test.txt')
#
#                       with cd(tmpdir), cuisine.mode_user(), settings(warn_only=True):
#                               listing = cuisine.run('ls -la test.txt').split()
#                               self.assertEqual('root', listing[2])  # user
#                               self.assertEqual('root', listing[3])  # group
#                               result = cuisine.run('cat test.txt')
#                               self.assertTrue(result.failed)
#                               self.assertIn('Permission denied', result)
#               finally:
#                       shutil.rmtree(tmpdir)

# NOTE: Test disabled for now
# class LocalExecution(unittest.TestCase):
#
#       def testFabricLocalCommands(self):
#               '''
#               Make sure local and lcd still work properly and that run and cd
#               in local mode don't interfere.
#               '''
#               tmpdir = tempfile.mkdtemp()
#               try:
#                       dir1 = os.path.join(tmpdir, 'test1')
#                       dir2 = os.path.join(tmpdir, 'test2')
#                       [os.mkdir(d) for d in [dir1, dir2]]
#
#                       with cd(dir1), fabric.api.lcd(dir2):
#                               file1 = os.path.join(dir1, 'test1.txt')
#                               cuisine.run('touch %s' % file1)
#
#                               file2 = os.path.join(dir2, 'test2.txt')
#                               fabric.api.local('touch %s' % file2)
#
#                               self.assertTrue(cuisine.file_exists(file2))
#               finally:
#                       shutil.rmtree(tmpdir)
#
#
#       def testResultAttributes(self):
#               failing_command = 'cat /etc/shadow'     # insufficient permissions
#               succeeding_command = 'uname -a'
#               erroneous_command = 'this-command-does-not-exist -a'
#
#               # A successful command should have the appropriate status
#               # attributes set
#               result = cuisine.run(succeeding_command)
#               self.assertTrue(result.succeeded)
#               self.assertFalse(result.failed)
#               self.assertEqual(result.return_code, 0)
#
#               # With warn_only set, we should be able to examine the result
#               # even if it fails
#               with settings(warn_only=True):
#                       # command should fail with output to stderr
#                       result = cuisine.run(failing_command, combine_stderr=False)
#                       self.assertTrue(result.failed)
#                       self.assertFalse(result.succeeded)
#                       self.assertEqual(result.return_code, 1)
#                       self.assertIsNotNone(result.stderr)
#                       self.assertIn('Permission denied', result.stderr)
#
#               # With warn_only off, failure should cause execution to abort
#               with settings(warn_only=False):
#                       with self.assertRaises(SystemExit):
#                               cuisine.run(failing_command)
#
#               # An erroneoneous command should fail similarly to fabric
#               with settings(warn_only=True):
#                       result = cuisine.run(erroneous_command)
#                       self.assertTrue(result.failed)
#                       self.assertEqual(result.return_code, 127)
#
#       def testCd(self):
#               with cd('/tmp'):
#                       self.assertEqual(cuisine.run('pwd'), '/tmp')
#
#       def testShell(self):
#               # Ensure that env.shell is respected by setting it to the
#               # 'exit' command and testing that it aborts.
#               with settings(use_shell=True, shell='exit'):
#                       with self.assertRaises(SystemExit):
#                               cuisine.run('ls')
#
#       def testSudoPrefix(self):
#               # Ensure that env.sudo_prefix is respected by setting it to
#               # echo the command to stdout rather than executing it
#               with settings(use_shell=True, sudo_prefix="echo %s"):
#                       cmd = 'ls -la'
#                       run_result = cuisine.run(cmd)
#                       sudo_result = cuisine.sudo(cmd)
#                       self.assertNotEqual(run_result.stdout, sudo_result.stdout)
#                       self.assertIn(env.shell, sudo_result)
#                       self.assertIn(cmd, sudo_result)
#
#       def testPath(self):
#               # Make sure the path is applied properly by setting it empty
#               # and making sure that stops a simple command from running
#               self.assertTrue(cuisine.run('ls').succeeded)
#
#               with fabric.api.path(' ', behavior='replace'), settings(warn_only=True):
#                       result = cuisine.run('ls', combine_stderr=False)
#                       self.assertTrue(result.failed)
#                       self.assertIn("command not found", result.stderr)


class Files(unittest.TestCase):

    def testRead(self):
        cuisine.file_read("/etc/passwd")

    def testWrite(self):
        content = "Hello World!"
        path = "/tmp/cuisine.test"
        cuisine.file_write(path, content, check=False)
        assert os.path.exists(path)
        with file(path) as f:
            assert f.read() == content
        os.unlink(path)

    def testSHA1(self):
        content = "Hello World!"
        path = "/tmp/cuisine.test"
        cuisine.file_write(path, content, check=False)
        sig = cuisine.file_sha256(path)
        with file(path) as f:
            file_sig = hashlib.sha256(f.read()).hexdigest()
        assert sig == file_sig

    def testExists(self):
        try:
            fd, path = tempfile.mkstemp()
            f = os.fdopen(fd, 'w')
            f.write('Hello World!')
            f.close()
            assert cuisine.file_exists(path)
        finally:
            os.unlink(path)

    def testAttribs(self):
        tmpdir = tempfile.mkdtemp()
        try:
            dir1_path = os.path.join(tmpdir, 'dir1')
            cuisine.dir_ensure(dir1_path)
            file1_path = os.path.join(dir1_path, 'file1')
            cuisine.file_write(file1_path, 'test', mode='666')
            cuisine.file_attribs(tmpdir, mode=644, recursive=True)
            attribs = cuisine.file_attribs_get(file1_path)
            self.assertEqual(attribs.get('mode'), '644')
        finally:
            cuisine.dir_remove(tmpdir, recursive=True)


class Dirs(unittest.TestCase):

    def testAttribs(self):
        tmpdir = tempfile.mkdtemp()
        try:
            dir1_path = os.path.join(tmpdir, 'dir1')
            cuisine.dir_ensure(dir1_path)
            file1_path = os.path.join(dir1_path, 'file1')
            cuisine.file_write(file1_path, 'test', mode='666')
            cuisine.dir_attribs(tmpdir, mode=755, recursive=True)
            attribs = cuisine.file_attribs_get(dir1_path)
            self.assertEqual(attribs.get('mode'), '755')
        finally:
            cuisine.dir_remove(tmpdir, recursive=True)


class Packages(unittest.TestCase):

    def testInstall(self):
        with cuisine.mode_sudo():
            cuisine.package_ensure("tree")
        self.assertTrue(cuisine.run("tree --version").startswith("tree "))


class SSHKeys(unittest.TestCase):

    key = "ssh-dss XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX= user@cuisine"""

    def testKeygen(self):
        pass
        #if cuisine.ssh_keygen(USER):
              #print "SSH keys already there"
        #else:
              #print "SSH keys created"

    # mode_local not working for these tests
    #def testAuthorize(self):
        #cuisine.ssh_authorize(USER, self.key)
        #d = cuisine.user_check(USER, need_passwd=False)
        #keyf = d["home"] + "/.ssh/authorized_keys"
        #keys = [line.strip() for line in open(keyf)]
        #assert keys.count(self.key) == 1

    #def testUnauthorize(self):
        #cuisine.ssh_unauthorize(USER, self.key)
        #d = cuisine.user_check(USER, need_passwd=False)
        #keyf = d["home"] + "/.ssh/authorized_keys"
        #keys = [line.strip() for line in open(keyf)]
        #assert keys.count(self.key) == 0

if __name__ == "__main__":
    # We bypass fabric as we want the tests to be run locally
    cuisine.mode_local()
    unittest.main()

# EOF
