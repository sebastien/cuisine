from ..api import APIModule
from ..decorators import logged, dispatch

# =============================================================================
#
# PACKAGE OPERATIONS
#
# =============================================================================


class PackageAPI(APIModule):

    @logged
    @dispatch(multiple=True)
    def package_available(self, package: str) -> bool:
        """Tells if the given package is available"""

    @logged
    @dispatch(multiple=True)
    def package_installed(self, package, update=False) -> bool:
        """Tells if the given package is installed or not."""

    @logged
    @dispatch(multiple=True)
    def package_upgrade(self, distupgrade=False):
        """Updates every package present on the system."""

    @logged
    @dispatch(multiple=True)
    def package_update(self, package=None):
        """Updates the package database (when no argument) or update the package
        or list of packages given as argument."""

    @logged
    @dispatch
    def package_install(self, package, update=False):
        """Installs the given package/list of package, optionally updating
        the package database."""

    @logged
    @dispatch(multiple=True)
    def package_ensure(self, package, update=False):
        """Tests if the given package is installed, and installs it in
        case it's not already there. If `update` is true, then the
        package will be updated if it already exists."""

    @logged
    @dispatch
    def package_clean(self, package=None):
        """Clean the repository for un-needed files."""

    @logged
    @dispatch(multiple=True)
    def package_remove(self, package, autoclean=False):
        """Remove package and optionally clean unused packages"""

# -----------------------------------------------------------------------------
# APT PACKAGE (DEBIAN/UBUNTU)
# -----------------------------------------------------------------------------


# @logged
# def repository_ensure_apt(repository):
#     package_ensure_apt('python-software-properties')
#     sudo("add-apt-repository --yes " + repository)
#
#
# def apt_get(cmd):
#     cmd = CMD_APT_GET + cmd
#     result = sudo(cmd)
#     # If the installation process was interrupted, we might get the following message
#     # E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a' to correct the problem.
#     if "sudo dpkg --configure -a" in result:
#         sudo("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
#         result = sudo(cmd)
#     return result
#
#
# def apt_cache(cmd):
#     cmd = CMD_APT_CACHE + cmd
#     return run(cmd)
#
#
# def package_available_apt(package: str) -> bool:
#     return apt_cache(f" search '^{quote_safe(package)}$'").has_value
#
#
# def package_update_apt(package=None):
#     if package == None:
#         return apt_get("-q --yes update")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         return apt_get(' install --only-upgrade ' + package)
#
#
# def package_upgrade_apt(distupgrade=False):
#     if distupgrade:
#         return apt_get("dist-upgrade")
#     else:
#         return apt_get("install --only-upgrade")
#
#
# def package_install_apt(package, update=False):
#     if update:
#         apt_get("update")
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     return apt_get("install " + package)
#
#
# def package_installed_apt(package, update=False) -> False:
#     pkg = package.strip()
#     if not pkg:
#         raise ValueError(f"Package argument is empty: {repr(package)}")
#     # The most reliable way to detect success is to use the command status
#     # and suffix it with OK. This won't break with other locales.
#     status = run(
#         f"dpkg-query -W -f='${{Status}} ' '{pkg}' && echo OK;true")
#     return status.last_line.endswith("OK")
#
#
# def package_ensure_apt(package, update=False):
#     """Ensure apt packages are installed"""
#     if isinstance(package, str):
#         package = package.split()
#     res = {}
#     for p in package:
#         p = p.strip()
#         if not p:
#             continue
#         # The most reliable way to detect success is to use the command status
#         # and suffix it with OK. This won't break with other locales.
#         status = run("dpkg-query -W -f='${Status} ' %s && echo OK;true" % p)
#         if not status.endswith("OK") or "not-installed" in status:
#             package_install_apt(p)
#             res[p] = False
#         else:
#             if update:
#                 package_update_apt(p)
#             res[p] = True
#     if len(res) == 1:
#         return next(_ for _ in res.values())
#     else:
#         return res
#
#
# def package_clean_apt(package=None):
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     return apt_get("-y --purge remove %s" % package)
#
#
# def package_remove_apt(package, autoclean=False):
#     apt_get('remove ' + package)
#     if autoclean:
#         apt_get("autoclean")
#
# # -----------------------------------------------------------------------------
# # YUM PACKAGE (RedHat, CentOS)
# # added by Prune - 20120408 - v1.0
# # -----------------------------------------------------------------------------
#
#
# def repository_ensure_yum(repository):
#     raise Exception("Not implemented for Yum")
#
#
# def package_upgrade_yum():
#     sudo("yum -y update")
#
#
# def package_update_yum(package=None):
#     if package == None:
#         sudo("yum -y update")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         sudo("yum -y upgrade " + package)
#
#
# def package_install_yum(package, update=False):
#     if update:
#         sudo("yum -y update")
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     sudo("yum -y install %s" % (package))
#
#
# def package_ensure_yum(package, update=False):
#     status = run("yum list installed %s ; true" % package)
#     if status.find("No matching Packages") != -1 or status.find(package) == -1:
#         package_install_yum(package, update)
#         return False
#     else:
#         if update:
#             package_update_yum(package)
#         return True
#
#
# def package_clean_yum(package=None):
#     sudo("yum -y clean all")
#
#
# def package_remove_yum(package, autoclean=False):
#     sudo("yum -y remove %s" % (package))
#
# # -----------------------------------------------------------------------------
# # ZYPPER PACKAGE (openSUSE)
# # -----------------------------------------------------------------------------
#
#
# def repository_ensure_zypper(repository):
#     repository_uri = repository
#     if repository[-1] != '/':
#         repository_uri = repository.rpartition("/")[0]
#     status = run("zypper --non-interactive --gpg-auto-import-keys repos -d")
#     if status.find(repository_uri) == -1:
#         sudo("zypper --non-interactive --gpg-auto-import-keys addrepo " + repository)
#         sudo("zypper --non-interactive --gpg-auto-import-keys modifyrepo --refresh " + repository_uri)
#
#
# def package_upgrade_zypper():
#     sudo("zypper --non-interactive --gpg-auto-import-keys update --type package")
#
#
# def package_update_zypper(package=None):
#     if package == None:
#         sudo("zypper --non-interactive --gpg-auto-import-keys refresh")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         sudo("zypper --non-interactive --gpg-auto-import-keys update --type package " + package)
#
#
# def package_install_zypper(package, update=False):
#     if update:
#         package_update_zypper()
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     sudo("zypper --non-interactive --gpg-auto-import-keys install --type package --name " + package)
#
#
# def package_ensure_zypper(package, update=False):
#     status = run(
#         "zypper --non-interactive --gpg-auto-import-keys search --type package --installed-only --match-exact %s ; true" % package)
#     if status.find("No packages found.") != -1 or status.find(package) == -1:
#         package_install_zypper(package)
#         return False
#     else:
#         if update:
#             package_update_zypper(package)
#         return True
#
#
# def package_clean_zypper():
#     sudo("zypper --non-interactive clean")
#
#
# def package_remove_zypper(package, autoclean=False):
#     sudo("zypper --non-interactive remove %s" % (package))
#
# # -----------------------------------------------------------------------------
# # PACMAN PACKAGE (Arch)
# # -----------------------------------------------------------------------------
#
#
# def repository_ensure_pacman(repository):
#     raise Exception("Not implemented for Pacman")
#
#
# def package_update_pacman(package=None):
#     if package == None:
#         sudo("pacman --noconfirm -Sy")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         sudo("pacman --noconfirm -S " + package)
#
#
# def package_upgrade_pacman():
#     sudo("pacman --noconfirm -Syu")
#
#
# def package_install_pacman(package, update=False):
#     if update:
#         sudo("pacman --noconfirm -Sy")
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     sudo("pacman --noconfirm -S %s" % (package))
#
#
# def package_ensure_pacman(package, update=False):
#     """Ensure apt packages are installed"""
#     if not isinstance(package, str):
#         package = " ".join(package)
#     status = run("pacman -Q %s ; true" % package)
#     if ('was not found' in status):
#         package_install_pacman(package, update)
#         return False
#     else:
#         if update:
#             package_update_pacman(package)
#         return True
#
#
# def package_clean_pacman():
#     sudo("pacman --noconfirm -Sc")
#
#
# def package_remove_pacman(package, autoclean=False):
#     if autoclean:
#         sudo('pacman --noconfirm -Rs ' + package)
#     else:
#         sudo('pacman --noconfirm -R ' + package)
#
# # -----------------------------------------------------------------------------
# # EMERGE PACKAGE (Gentoo Portage)
# # added by davidmmiller - 20130417 - v0.1 (status - works for me...)
# # -----------------------------------------------------------------------------
#
#
# def repository_ensure_emerge(repository):
#     raise Exception("Not implemented for emerge")
#     """This will be used to add Portage overlays in a future update."""
#
#
# def package_upgrade_emerge(distupgrade=False):
#     sudo("emerge -q --update --deep --newuse --with-bdeps=y world")
#
#
# def package_update_emerge(package=None):
#     if package == None:
#         sudo("emerge -q --sync")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         sudo("emerge -q --update --newuse %s" % package)
#
#
# def package_install_emerge(package, update=False):
#     if update:
#         sudo("emerge -q --sync")
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     sudo("emerge -q %s" % (package))
#
#
# def package_ensure_emerge(package, update=False):
#     if not isinstance(package, str):
#         package = " ".join(package)
#     if update:
#         sudo("emerge -q --update --newuse %s" % package)
#     else:
#         sudo("emerge -q --noreplace %s" % package)
#
#
# def package_clean_emerge(package=None):
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     if package:
#         sudo("CONFIG_PROTECT='-*' emerge --quiet-unmerge-warn --unmerge %s" % package)
#     else:
#         sudo('emerge -q --depclean')
#         sudo('revdep-rebuild -q')
#
#
# def package_remove_emerge(package, autoclean=False):
#     if autoclean:
#         sudo('emerge --quiet-unmerge-warn --unmerge ' + package)
#         sudo('emerge -q --depclean')
#         sudo('revdep-rebuild -q')
#     else:
#         sudo('emerge --quiet-unmerge-warn --unmerge ' + package)
#
# # -----------------------------------------------------------------------------
# # PKGIN (Illumos, SmartOS, BSD, OSX)
# # added by lbivens - 20130520 - v0.5 (this works but can be better)
# # -----------------------------------------------------------------------------
#
# # This should be simple but I have to think it properly
#
#
# def repository_ensure_pkgin(repository):
#     raise Exception("Not implemented for pkgin")
#
#
# def package_upgrade_pkgin():
#     sudo("pkgin -y upgrade")
#
#
# def package_update_pkgin(package=None):
#     # test if this works
#     if package == None:
#         sudo("pkgin -y update")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         sudo("pkgin -y upgrade " + package)
#
#
# def package_install_pkgin(package, update=False):
#     if update:
#         sudo("pkgin -y update")
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     sudo("pkgin -y install %s" % (package))
#
#
# def package_ensure_pkgin(package, update=False):
#     # I am gonna have to do something different here
#     status = run("pkgin list | grep %s ; true" % package)
#     if status.find("No matching Packages") != -1 or status.find(package) == -1:
#         package_install(package, update)
#         return False
#     else:
#         if update:
#             package_update(package)
#         return True
#
#
# def package_clean_pkgin(package=None):
#     sudo("pkgin -y clean")
#
#
# # -----------------------------------------------------------------------------
# # PKG - FreeBSD
# # -----------------------------------------------------------------------------
#
# def repository_ensure_pkgng(repository):
#     raise Exception("Not implemented for pkgng")
#
#
# def package_upgrade_pkgng():
#     sudo("echo y | pkg upgrade")
#
#
# def package_update_pkgng(package=None):
#     # test if this works
#     if package == None:
#         sudo("pkg -y update")
#     else:
#         if type(package) in (list, tuple):
#             package = " ".join(package)
#         sudo("pkg upgrade " + package)
#
#
# def package_install_pkgng(package, update=False):
#     if update:
#         sudo("pkg update")
#     if type(package) in (list, tuple):
#         package = " ".join(package)
#     sudo("echo y | pkg install %s" % (package))
#
#
# def package_ensure_pkgng(package, update=False):
#     # I am gonna have to do something different here
#     status = run("pkg info %s ; true" % package)
#     if status.find("No package(s) matching") != -1 or status.find(package) == -1:
#         package_install_pkgng(package, update)
#         return False
#     else:
#         if update:
#             package_update_pkgng(package)
#         return True
#
#
# def package_clean_pkgng(package=None):
#     sudo("pkg delete %s" % (package))
