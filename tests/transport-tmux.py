from cuisine.connection.local import LocalConnection
from cuisine.connection.tmux import Tmux
import time

new_session = f"XXX_{time.time()}".replace('.', '_')

tmux = Tmux(LocalConnection())
original_sessions = tmux.session_list()
assert new_session not in original_sessions
assert not tmux.session_has(new_session)

tmux.session_ensure(new_session)
assert new_session in tmux.session_list()

tmux.session_kill(new_session)
assert new_session not in tmux.session_list()

# This is only true if there is no concurrent test
assert tmux.session_list() == original_sessions

# EOF
