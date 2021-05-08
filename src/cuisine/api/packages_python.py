from ..decorators import dispatch

# =============================================================================
#
# PYTHON PACKAGE OPERATIONS
#
# =============================================================================


@dispatch('python_package', multiple=True)
def python_package_upgrade(package):
    '''
    Upgrades the defined python package.
    '''


@dispatch('python_package', multiple=True)
def python_package_install(package=None):
    '''
    Installs the given python package/list of python packages.
    '''


@dispatch('python_package', multiple=True)
def python_package_ensure(package):
    '''
    Tests if the given python package is installed, and installes it in
    case it's not already there.
    '''


@dispatch('python_package', multiple=True)
def python_package_remove(package):
    '''
    Removes the given python package.
    '''


class PythonPIPPackage:


    def python_package_upgrade_pip(self, package, pip=None):
        '''
        The "package" argument, defines the name of the package that will be upgraded.
        '''
        pip = self.command("pip")
        self.run('%s install --upgrade %s' % (pip, package))


    def python_package_install_pip(self,package=None, r=None, pip=None):
        '''
        The "package" argument, defines the name of the package that will be installed.
        The argument "r" referes to the requirements file that will be used by pip and
        is equivalent to the "-r" parameter of pip.
        Either "package" or "r" needs to be provided
        The optional argument "E" is equivalent to the "-E" parameter of pip. E is the
        path to a virtualenv. If provided, it will be added to the pip call.
        '''
        pip = self.command("pip")
        if package:
            self.run('%s install %s' % (pip, package))
        elif r:
            self.run('%s install -r %s' % (pip, r))
        else:
            raise Exception(
                "Either a package name or the requirements file has to be provided.")


    def python_package_ensure_pip(self,package=None, r=None, pip=None):
        '''
        The "package" argument, defines the name of the package that will be ensured.
        The argument "r" referes to the requirements file that will be used by pip and
        is equivalent to the "-r" parameter of pip.
        Either "package" or "r" needs to be provided
        '''
        # FIXME: At the moment, I do not know how to check for the existence of a pip package and
        # I am not sure if this really makes sense, based on the pip built in functionality.
        # So I just call the install functions
        pip = self.command("pip")
        python_package_install_pip(package, r, pip)


    def python_package_remove_pip(self, package, pip=None):
        '''
        The "package" argument, defines the name of the package that will be ensured.
        The argument "r" referes to the requirements file that will be used by pip and
        is equivalent to the "-r" parameter of pip.
        Either "package" or "r" needs to be provided
        '''
        pip = self.command("pip")
        return run('%s uninstall %s' % (pip, package))

# -----------------------------------------------------------------------------
# EASY_INSTALL PYTHON PACKAGE MANAGER
# -----------------------------------------------------------------------------

class PythonEIPackage:

    def python_package_upgrade_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be upgraded.
        '''
        self.run(f"{command('easy_install')} --upgrade '{package}")


    def python_package_install_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be installed.
        '''
        self.run(f"{command('easy_install')} '{package}")


    def python_package_ensure_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be ensured.
        '''
        # FIXME: At the moment, I do not know how to check for the existence of a py package and
        # I am not sure if this really makes sense, based on the easy_install built in functionality.
        # So I just call the install functions
        self.python_package_install_easy_install(package)


    def python_package_remove_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be removed.
        '''
        # FIXME: this will not remove egg file etc.
        self.run(f"{self.command('easy_install')} -m '{package}")

# EOF
