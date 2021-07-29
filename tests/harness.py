import sys
import os
import subprocess
import shutil
import time

# --
# # Harness
#
# Harness is a very simple test runner that follows the idea of the
# [Test Anything Protocol](http://testanything.org/) with a focus on nicer
# looking, more parseable output.
#
# Note that the implementation uses binary output as we never know what the
# commands might spit out.

ENCODING = sys.stdout.encoding
QUIET = os.getenv("QUIET", "").lower() in ("1", "true")
RUNNERS = {
    "py": os.getenv("PYTHON", "python"),
    "sh": os.getenv("BASH", "bash"),
}


TMPDIR = os.path.abspath(".tmp")


def run(path: str, out, quiet=QUIET):
    out(b"-- TEST ")
    out(bytes(path, ENCODING))
    out(b"\n")
    now = time.time()
    # We create a temporary directory
    if not os.path.exists(TMPDIR):
        os.mkdir(TMPDIR)
    os.environ["TESTDIR"] = TMPDIR
    res = subprocess.run(
        [RUNNERS[path.rsplit(".", 1)[-1]], path],  stdout=subprocess.PIPE)
    shutil.rmtree(TMPDIR)
    oks = 0
    fails = 0
    if (success := res.returncode == 0):
        for line in res.stdout.split(b"\n"):
            if line.startswith(b"!! FAIL "):
                fails += 1
                if not quiet:
                    out(b"!! \t")
            elif line.startswith(b".. OK "):
                oks += 1
                if not quiet:
                    out(b".. \t")
            elif not quiet:
                out(b"\t")
            if not quiet:
                out(line)
                out(b"\n")
    if success and not fails:
        out(b".. OK")
    else:
        out(b"!! FAIL")
    out(bytes(f" TIME {time.time() - now:0.2f}s ", ENCODING))
    out(bytes(path, ENCODING))
    out(b"\n")
    return success and not fails


def run_tests(args=sys.argv[1:], out=lambda _: None):
    success = True
    now = time.time()
    out(bytes(f"-- TEST Harness EXPECT {len(args)}\n", ENCODING))
    for path in args:
        success = success and run(path, out)
        if not success:
            out(b"!! FAIL ")
            out(bytes(path, ENCODING))
            return False
    out(bytes(f".. OK TIME {time.time() - now:0.2f}s\n", ENCODING))
    return True


if __name__ == "__main__":
    with open("/dev/stdout", "wb") as f:
        sys.exit(0 if run_tests(out=f.write) else 1)

# EOF
