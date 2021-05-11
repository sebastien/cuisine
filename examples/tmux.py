from cuisine import connect_tmux, run
with connect_tmux(session="cuisine", window="0"):
    print("Run on TMUX:", run('echo "$TMUX"'))
print("Run locally:", run('echo "$TMUX"'))

# EOF
