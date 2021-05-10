from ..api import APIModule
from ..decorators import dispatch, expose


class PythonPackageAPI(APIModule):

    @expose
    def select_python_package(self, type: str) -> bool:
        return True

    @expose
    def detect_python_package(self) -> str:
        """Automatically detects the type of package"""
        return "pip"

    @expose
    @dispatch('python_package', multiple=True)
    def python_package_upgrade(self, package):
        """Upgraded the given Python package"""

    @expose
    @dispatch('python_package', multiple=True)
    def python_package_install(self, package=None):
        """Installs the given python package/list of python packages."""

    @expose
    @dispatch('python_package', multiple=True)
    def python_package_ensure(self, package):
        """Tests if the given python package is installed, and installs it in
        case it's not already there."""

    @expose
    @dispatch('python_package', multiple=True)
    def python_package_remove(self, package):
        """Removes the given python package. """


class PythonPIPPackage(APIModule):

    @expose
    def python_package_upgrade_pip(self, package=None, local=True):
        pip = self.api.config_command("pip")
        self.api.run(
            f"{pip} install {'--user' if local else ''} --upgrade {package}")

    @expose
    def python_package_install_pip(self, package=None, local=True):
        pip = self.api.config_command("pip")
        self.api.run(
            f"{pip} install {'--user' if local else ''} --upgrade {package}")

    @expose
    def python_package_ensure_pip(self, package=None, local=True):
        pip = self.api.config_command("pip")
        self.api.run(
            f"{pip} install {'--user' if local else ''} --upgrade {package}")

    @expose
    def python_package_remove_pip(self, package, local=True):
        pip = self.api.config_command("pip")
        self.api.run(
            f"${pip} install {'--user' if local else ''} --upgrade {package}")


class PythonEIPackage:

    @expose
    def python_package_upgrade_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be upgraded.
        '''
        self.api.run(
            f"{self.api.config_command('easy_install')} --upgrade '{package}")

    @expose
    def python_package_install_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be installed.
        '''
        self.api.run(f"{self.api.config_command('easy_install')} '{package}")

    @expose
    def python_package_ensure_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be ensured.
        '''
        # FIXME: At the moment, I do not know how to check for the existence of a py package and
        # I am not sure if this really makes sense, based on the easy_install built in functionality.
        # So I just call the install functions
        self.python_package_install_easy_install(package)

    @expose
    def python_package_remove_easy_install(self, package):
        '''
        The "package" argument, defines the name of the package that will be removed.
        '''
        # FIXME: this will not remove egg file etc.
        self.api.run(
            f"{self.api.config_command('easy_install')} -m '{package}")

# EOF
