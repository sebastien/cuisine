from cuisine import *
import threading
import time


def writer():
    for _ in range(10):
        run("date '+%T' >> streaming.txt")
        time.sleep(1)


t = threading.Thread(target=writer)
t.start()

run("touch streaming.txt")
res = run("timeout 10 tail -f streaming.txt")
run("unlink streaming.txt")
print(res.lines)

t.join()
# EOF
