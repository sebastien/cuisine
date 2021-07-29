from ..api import APIModule as API
from ..utils import quoted, make_options_str
from ..decorators import logged, expose, dispatch, requires, variant
from typing import Optional, Dict
import base64


# TODO: User_list
class UserAPI(API):

    @expose
    def detect_user(self) -> str:
        # TODO: Detects the variant
        return "linux"

    @expose
    @dispatch("user")
    def user_passwd(self, name: str, passwd: str, encrypted_passwd=True):
        """Sets the given user password. Password is expected to be encrypted by default."""

    @expose
    @dispatch("user")
    def user_create(self, name: str, passwd: Optional[str] = None,
                    home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None,
                    shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None,
                    encrypted_passwd: Optional[bool] = True,
                    fullname: Optional[str] = None, create_home: Optional[bool] = True):
        """Creates the user with the given name, optionally giving a
        specific password/home/uid/gid/shell."""

    @expose
    @dispatch("user")
    def user_get(self, name: Optional[str] = None, uid: Optional[int] = None) -> Dict:
        """Checks if there is a user defined with the given name,
        returning its information as a
        '{"name":<str>,"uid":<str>,"gid":<str>,"home":<str>,"shell":<str>}'
        or 'None' if the user does not exists.
        need_passwd (Boolean) indicates if password to be included in result or not.
                If set to True it parses 'getent shadow' and needs sudo access
        """

    @expose
    @dispatch("user")
    def user_ensure(self, name: str, passwd: Optional[str] = None,
                    home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None,
                    shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None,
                    encrypted_passwd: Optional[bool] = True,
                    fullname: Optional[str] = None, create_home: Optional[bool] = True):
        """Ensures that the given users exists, optionally updating their
        passwd/home/uid/gid/shell."""

    @expose
    @dispatch("user")
    def user_exists(self, name: str) -> bool:
        """Tells if the user exists."""

    @expose
    @dispatch("user")
    def user_remove(self, name: str, remove_home: bool = False):
        """Removes the user with the given name, optionally
        removing the home directory and mail spool."""

# --
# ## Linux User API
#
# This implements the user functions for Linux.


class LinuxUserAPI(API):

    @expose
    @variant("linux")
    @requires("usermod", "openssl", "chpasswd")
    def user_passwd_linux(self, name: str, passwd: str, encrypted_passwd=True):
        """Sets the given user password. Password is expected to be encrypted by default."""
        encoded_password = base64.b64encode(bytes(f"{name}:{passwd}", "utf8"))
        if encrypted_passwd:
            self.api.sudo(
                f"usermod -p {quoted(passwd)} {quoted(name)}")
        else:
            # NOTE: We use base64 here in case the password contains special chars
            # TODO: Make sure this openssl command works everywhere, maybe we should use a text_base64_decode?
            self.api.sudo(
                f"echo {quoted(encoded_password)} | openssl base64 -A -d | chpasswd")

    @expose
    @variant("linux")
    @requires("useradd")
    def user_create_linux(self, name: str, passwd: Optional[str] = None,
                          home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None,
                          shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None,
                          encrypted_passwd: Optional[bool] = True,
                          fullname: Optional[str] = None, create_home: Optional[bool] = True):
        options = make_options_str({
            "-d ": home,
            "-u ": uid,
            # TODO: We don't have groups updated yet
            # "-g ": gid if gid != None else name if self.api.group_exists(name) else None,
            "-g ": gid,
            "-s ": shell,
            "-K UID_MIN=": uid_min,
            "-K UID_MAX=": uid_max,
            "-c ": fullname,
            "-m": create_home,
        })
        self.api.sudo(f"useradd {options} {quoted(name)}")
        if passwd:
            self.api.user_passwd(name=name, passwd=passwd,
                                 encrypted_passwd=encrypted_passwd)

    @expose
    @variant("linux")
    @requires("getent")
    def user_get_linux(self, name: str = None, uid: int = None):
        assert name != None or uid != None, "user_check: either `uid` or `name` should be given"
        assert name is None or uid is None, "user_check: `uid` and `name` both given, only one should be provided"
        for line in self.api.run("getent passwd").lines:
            fields = line.split(":")
            if len(fields) < 7:
                continue
            name, _, uid, gid, fullname, home, shell = fields[0:7]
            if name == name or uid == uid:
                return dict(name=name, uid=uid, gid=gid, fullname=fullname, home=home, shell=shell)
        return None

    @expose
    @variant("linux")
    @requires("usermod")
    def user_ensure_linux(self, name: str, passwd: Optional[str] = None,
                          home: Optional[str] = None, uid: Optional[int] = None, gid: Optional[int] = None,
                          shell: Optional[str] = None, uid_min: Optional[int] = None, uid_max: Optional[int] = None,
                          encrypted_passwd: Optional[bool] = True,
                          fullname: Optional[str] = None, create_home: Optional[bool] = True):
        if not self.api.user_exists(name):
            self.api.user_create(name, passwd, home, uid, gid, shell,
                                 fullname=fullname, encrypted_passwd=encrypted_passwd)
        else:
            profile = self.api.user_get(name)
            options = make_options_str({
                "-d ": home if profile.get("home") != home else None,
                "-u ": uid if profile.get("uid") != uid else None,
                "-g ": gid if profile.get("gid") != gid else None,
                "-s ": shell if profile.get("shell") != shell else None,
                "-c ": fullname if profile.get("fullname") != fullname else None,
            })
            if options:
                self.api.sudo(f"usermod {options} {quoted(name)}")
            if passwd:
                self.api.user_passwd(name=name, passwd=passwd,
                                     encrypted_passwd=encrypted_passwd)

    @expose
    @variant("linux")
    @requires("id")
    def user_exists_linux(self, name: str) -> bool:
        return self.api.run(f"id -u {quoted(name)}").is_success

    @expose
    @variant("linux")
    @requires("userdel")
    def user_remove_linux(self, name: str, remove_home: bool = False):
        """Removes the user with the given name, optionally
        removing the home directory and mail spool."""
        options = "-rf" if remove_home else "-f"
        self.api.sudo(f"userdel {options} {quoted(name)}")


# EOF
