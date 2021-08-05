from ..api import APIModule
from ..decorators import logged, dispatch, variant, expose
from ..connection.tmux import Tmux, TmuxConnection
from typing import List


class TmuxAPI(APIModule):

    @property
    def _tmux(self) -> Tmux:
        c = self.api.connection_like(
            lambda _: not isinstance(_, TmuxConnection))
        assert c, "Could not find a suitable connection for creating a Tmux instance"
        return Tmux(c)

    @expose
    def tmux_session_list(self) -> List[str]:
        return self._tmux.session_list()

    @expose
    def tmux_window_list(self, session: str) -> List[str]:
        return self._tmux.window_list(session)

    @expose
    def tmux_is_responsive(self, session: str, window: str) -> bool:
        return self._tmux.is_responsive(session, window)


# EOF
