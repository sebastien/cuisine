import os
import mitogen
try:
    from cuisine import run_local, run_local_raw

except ImportError as e:
    print("You need 'cuisine' in your $PYTHONPATH, or run 'appenv' <https://github/sebastien/appenv>")


def run(cmd):
    os.system(cmd)


@mitogen.main()
def main(router):
    context = router.ssh(hostname="localhost")
    # TODO: We need (stdout, stderr, exit)
    res = context.call(run, "echo 'Hello, World!'")
    print(f"OK: mitogen.run()={res}")
    res = context.call(run_local_raw, "echo 'Hello, World!'")
    print(f"OK: mitogen.run_local_raw()={res}")
    try:
        res = context.call(run_local, "echo 'Hello, World!'")
        print(f"OK: mitogen.run_local()={res}")
    except mitogen.core.StreamError as e:
        # The takeaway here is that Mitogen is good for communicating raw data (ie. something
        # that can be sent as JSON), but not for complex objects. Here's another
        # argument for data-oriented programming.
        print(f"FAIL: mitogen.run_local()={e}")
    print("END")
# EOF
