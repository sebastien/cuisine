#!/usr/bin/env python
from distutils.core import setup

setup(
	name = "cuisine",
	packages = ["cuisine",],
	version = "0.0.1",
	description = "Chef-like functionality for Fabric",
	author = "Sebastien Pierre",
	author_email = "sebastien.pierre@gmail.com",
	url = "http://type-z.org/sebastien",
	download_url = "https://github.com/sebastien/cuisine",
	install_requires = ['fabric',],
	keywords = ["fabric", "chef", "ssh",],
	classifiers = [
		"Programming Language :: Python",
		"Development Status :: 3 - Alpha",
		"Natural Language :: English",
		"Environment :: Web Environment",
		"Intended Audience :: Developers",
		"Operating System :: OS Independent",
		"Topic :: Utilities"
		],
)

