from ..api import APIModule as API
from ..decorators import logged, expose, dispatch, requires, variant
from ..utils import quoted, make_options_str
from typing import Optional, cast
from pathlib import Path
import os

# --
# ## SSH API
#
# The SSH API makes it easy to create keys, add and remove authorized keys
# for created users.


class SSHAPI(API):

    @expose
    @requires("ssh-keygen")
    def ssh_keygen(self, user: str, keytype="rsa") -> str:
        """Generates a pair of ssh keys in the user's home .ssh directory."""
        assert self.api.user_exists(user), "User"
        home = self.api.user_get(user).get("home")
        assert home, f"User has no home field: {user}"
        key_file_priv = f"{home}/.ssh/id_{keytype}"
        key_file_pub = f"{keyfile}.pub"
        if not self.api.file_exists(key_file_priv):
            self.api.dir_ensure(
                f"{home}/.ssh", mode="0700", owner=user, group=user)
            run("ssh-keygen -q -t {keytype} -f {quoted(key_file_priv)} -N ''")
            # TODO: We might want to check the mode as well
            file_attribs(key_file_priv, owner=user, group=user)
            file_attribs(key_file_pub, owner=user, group=user)
            return key_file_priv
        else:
            return key_file_priv

    @expose
    def ssh_authorize(self, user: str, key: Optional[str] = None) -> bool:
        """Adds the given key to the '.ssh/authorized_keys' for the given
        user."""
        profile = self.api.user_get(user)
        group = profile["gid"]
        authorized_keys = f"{profile['home']}/.ssh/authorized_keys"
        if not key:
            # TODO: Should probably look for other types of keys
            key = Path("~/.ssh/id_rsa.pub").expanduser().read_text()
        key = cast(str, f"{key}\n" if not key.endswith("\n") else key)
        if not self.api.file_exists(authorized_keys):
            # Make sure that .ssh directory exists, see #42
            self.api.dir_ensure(os.path.dirname(
                authorized_keys), owner=user, group=group, mode="700")
            self.api.file_write(authorized_keys, key,
                                owner=user, group=group, mode="600")
            return True
        else:
            text = self.api.file_read_str(authorized_keys)
            if not next((_ for _ in text.split("\n") if _.startswith(key)), False):
                self.api.file_append(authorized_keys, key,
                                     owner=user, group=group, mode="0600")
                return True
            else:
                return False

    @expose
    def ssh_unauthorize(self, user: str, key: str):
        """Removes the given key to the remote '.ssh/authorized_keys' for the given
        user."""
        key = key.strip()
        profile = self.api.user_get(user)
        group = profile["gid"]
        authorized_keys = f"{profile['home']}/.ssh/authorized_keys"
        if self.api.file_exists(authorized_keys):
            lines = [_ for _ in self.api.file_read(
                authorized_keys).split("\n")]
            filtered = [_ for _ in lines if _.strip != key]
            if len(lines) != (filtered):
                # We only write the file if we changed
                self.api.file_write(authorized_keys, "\n".join(
                    filtered), owner=user, group=group, mode="600")
                return True
            else:
                return False
        else:
            return False

# EOF
