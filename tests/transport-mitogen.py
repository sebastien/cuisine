import os
import subprocess, threading
import mitogen

def run(cmd):
    os.system(cmd)

def run_local(command, sudo=False, shell=True, pty=True, combine_stderr=None):
    """
    Note: pty option exists for function signature compatibility and is
    ignored.
    """
    # TODO: We should retrieve the locale from the environment
    terminal_encoding = "utf8"
    # TODO: Pass the SUDO_PASSWORD variable to the command here
    if sudo:
        command = "sudo " + command
    # TODO: We might want to rework how we manage the CWD. In Fabric, that was lpwd
    run_in = "."
    process = subprocess.Popen(
        command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=run_in)
    # NOTE: This is not ideal, but works well.
    # See http://stackoverflow.com/questions/15654163/how-to-capture-streaming-output-in-python-from-subprocess-communicate
    # At some point, we should use a single thread.
    out = []
    err = []
    # FIXME: This does not seem to stream

    def stdout_reader():
        for line in process.stdout:
            line = str(line or b"", terminal_encoding)
            if line:
                log_debug(line.rstrip("\n").rstrip("\r"))
            out.append(line)

    def stderr_reader():
        for line in process.stderr:
            line = str(line or b"", terminal_encoding)
            log_error(line.rstrip("\n").rstrip("\r"))
            err.append(line)
    t0 = threading.Thread(target=stdout_reader)
    t1 = threading.Thread(target=stderr_reader)
    t0.start()
    t1.start()
    process.wait()
    t0.join()
    t1.join()
    out = "".join(out)
    err = "".join(err)
    # Error handling
    status = process.returncode
    return (command, status, out, err)


# TODO: We want to retrieve the value
@mitogen.main()
def main(router):
    context = router.ssh(hostname="localhost")
    # TODO: We need (stdout, stderr, exit)
    res = context.call(run, "echo 'Hello, World!'")
    print (f"mitogen.run()={res}")
    res = context.call(run_local, "echo 'Hello, World!'")
    print (f"mitogen.run_local()={res}")

# EOF
