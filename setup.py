#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


here = os.path.abspath(os.path.dirname(__file__))

DESCRIPTION = "Chef-like functionality for Fabric."

try:
    LONG_DESCRIPTION = open(os.path.join(here, "README.rst")).read()
except IOError:
    LONG_DESCRIPTION = ""

CLASSIFIERS = (
    "Programming Language :: Python",
    "Development Status :: 3 - Alpha",
    "Natural Language :: English",
    "Environment :: Web Environment",
    "Intended Audience :: Developers",
    "Operating System :: OS Independent",
    "Topic :: Utilities"
)


setup(name="cuisine",
      packages=["cuisine"],
      version="0.0.3",
      platforms=["any"],
      install_requires=["fabric"],

      author="Sébastien Pierre",
      author_email="sebastien.pierre@gmail.com",
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      classifiers=CLASSIFIERS,
      keywords=["fabric", "chef", "ssh"],
      url="http://github.com/sebastien",
      download_url="https://github.com/sebastien/cuisine",
)

# EOF - vim: ts=4 sw=4 noet
