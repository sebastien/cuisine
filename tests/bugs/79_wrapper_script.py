from cuisine import *

def test():
	with mode_local():
		name = run("whoami")
	print "NAME", repr(name)
	d = sudo("cat /etc/passwd | egrep '^%s:' ; true" % (name), pty=False)
	print repr(d)

#EOF
