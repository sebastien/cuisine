#!/usr/bin/env python
 
from distutils.core import setup
 
setup(name = "cuisine",
	version = "0.0.1",
	description = "Chef-like functionality for Fabric",
	author = "Sebastien Pierre",
	author_email = "sebastien.pierre@gmail.com",
	url = "https://github.com/sebastien/cuisine",
	install_requires=['fabric',],
	py_modules = ['cuisine',],
)
