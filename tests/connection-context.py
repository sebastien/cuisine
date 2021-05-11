from cuisine import connect_tmux, run, disconnect
# --
# Tests if the connection context works properly.
# --
# # Using the context
# We're using the connection context here and running two
# commands, one in the Tmux environment, one in the local environment.
# --
assert not (run('echo "$TMUX"').value)
with connect_tmux(session="cuisine", window="0"):
    assert run('echo "$TMUX"').value
assert not run('echo "$TMUX"').value, "Should be in the local environment"
# --
# # Not using the context
# If we're not using the context, then any command will be ran
# inside the connection until we disconnect.
# --
connect_tmux(session="cuisine", window="0")
assert run('echo "$TMUX"').value
disconnect()
assert not run('echo "$TMUX"').value
# EOF
