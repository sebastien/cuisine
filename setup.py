#!/usr/bin/env python
#encoding: utf-8
from distutils.core import setup
import os, sys
VERSION = eval(filter(lambda _:_.startswith("VERSION"), file("src/cuisine.py").readlines())[0].split("=")[1])
setup(
	name             = "cuisine",
	version          = VERSION,
	packages         = ["cuisine",],
	py_modules       = ["cuisine",],
	package_dir      = {'':'src'},
	description      = "Chef-like functionality for Fabric",
	author           = "Sébastien Pierre",
	author_email     = "sebastien.pierre@gmail.com",
	url              = "http://github.com/sebastien/cuisine",
	download_url     = "https://github.com/sebastien/cuisine/tarball/%s" % (VERSION),
	install_requires = ['fabric',],
	keywords         = ["fabric", "chef", "ssh",],
	classifiers      = [
		"Programming Language :: Python",
		"Development Status :: 3 - Alpha",
		"Natural Language :: English",
		"Environment :: Web Environment",
		"Intended Audience :: Developers",
		"Operating System :: OS Independent",
		"Topic :: Utilities"
		],
)
# EOF - vim: ts=4 sw=4 noet
