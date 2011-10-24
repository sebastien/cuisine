::

               /      /
     ___         ___    ___  ___
    |    |   )| |___ | |   )|___)
    |__  |__/ |  __/ | |  / |__

    -- Chef-like functionality for Fabric


About
-----
`Fabric <http://fabfile.org>`_ is an incredible tool to automate administration
of remote machines. As Fabric's function are rather low-level, you'll probably
quickly see a need for more high-level functions such as add/remove users and
groups, install/upgrade packages, etc.

Cuisine is a small set of functions that sit on top of Fabric, to abstract
common administration operations such as file/dir operations, user/group creation,
package install/upgrade, making it easier to write portable administration
and deployment scripts.

Cuisine's features are:

* Small, easy to read, a single file API: <object>_<operation>() e.g.
  dir_exists(location) tells if there is a remote directory at the
  given location.
* Covers file/dir operations, user/group operations, package
  operations
* Text processing and template functions
* All functions are lazy: they will actually only do things when the
  change is required.


Installation
------------
cuisine is on PyPI so you can either use ``easy_install -U cuisine``
or ``pip install cuisine`` to install it. Otherwise, you can download
the source from `GitHub <http://github.com/sebastien/cuisine>`_ and
run ``python setup.py install``.


More?
-----
If you want more information, you can:

* Check out Cuisine's API documentation below
* Read the `presentation on Cuisine <http://ur1.ca/45ku5>`_
