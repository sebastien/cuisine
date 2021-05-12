from ..api import APIModule
from ..decorators import logged, dispatch, variant, expose
from ..connection.tmux import Tmux
from typing import List


class TmuxAPI(APIModule):

    @expose
    def tmux_session_list(self) -> List[str]:
        return Tmux(self.api.connection()).session_list()

    @expose
    def tmux_window_list(self, session: str) -> List[str]:
        return Tmux(self.api.connection()).window_list(session)


# EOF
