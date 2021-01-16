#!/usr/bin/env python3

if __name__ != "__main__":
    quit(1)

import os, subprocess, time, signal
import multiprocessing


def try_unlink(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def wait_until_exists(path):
    for i in range(100):
        if os.path.exists(path):
            return True
        time.sleep(0.01)
    else:
        return False


def safe_cleanup(process):
    assert type(process) == subprocess.Popen
    for i in range(3):
        if process.poll() is None:
            # certain weston client programs appear to initiate shutdown proceedings correctly; however, they appear to wait for a frame beforehand, and the headless weston doesn't ask for additional frames
            process.send_signal(signal.SIGINT)
            time.sleep(0.5)
    try:
        process.wait(100)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(1)
        except subprocess.TimeoutExpired:
            # no third chances
            process.terminate()


weston_path = os.environ["TEST_WESTON_PATH"]
waypipe_path = os.environ["TEST_WAYPIPE_PATH"]
ld_library_path = (
    os.environ["LD_LIBRARY_PATH"] if "LD_LIBRARY_PATH" in os.environ else ""
)

sub_tests = {
    "SHM": ["TEST_WESTON_SHM_PATH"],
    "EGL": ["TEST_WESTON_EGL_PATH", "-o"],
    "DMABUF": ["TEST_WESTON_DMA_PATH"],
    "TERM": ["TEST_WESTON_TERM_PATH"],
    "PRES": ["TEST_WESTON_PRES_PATH"],
    "SUBSURF": ["TEST_WESTON_SUBSURF_PATH"],
}
for k, v in list(sub_tests.items()):
    if v[0] in os.environ:
        v[0] = os.environ[v[0]]
    else:
        del sub_tests[k]

xdg_runtime_dir = os.path.abspath("./run/")


# weston does not currently appear to support setting absolute socket paths
socket_path = "w_sock"
abs_socket_path = os.path.join(xdg_runtime_dir, socket_path)

mainenv = {"XDG_RUNTIME_DIR": xdg_runtime_dir, "LD_LIBRARY_PATH": ld_library_path}

weston_command = [
    weston_path,
    "--backend=headless-backend.so",
    "--socket=" + socket_path,
    # "--use-pixman",
    "--width=1111",
    "--height=777",
]

arguments = subprocess.check_output([weston_path, "--help"]).decode()
if "--use-gl" in arguments:
    weston_command.append("--use-gl")

try:
    import psutil
except ImportError:
    psutil = None

nontrivial_failures = False

subenv = {
    "WAYLAND_DISPLAY": abs_socket_path,
    "WAYLAND_DEBUG": "1",
    "XDG_RUNTIME_DIR": xdg_runtime_dir,
    "LD_LIBRARY_PATH": ld_library_path,
    "ASAN_OPTIONS": "detect_leaks=0",
}

wp_serv_env = {
    "WAYLAND_DEBUG": "1",
    "XDG_RUNTIME_DIR": xdg_runtime_dir,
    "LD_LIBRARY_PATH": ld_library_path,
    "ASAN_OPTIONS": "detect_leaks=0",
}

subproc_args = {"env": subenv, "stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT}

wp_serv_args = {
    "env": wp_serv_env,
    "stdin": subprocess.DEVNULL,
    "stderr": subprocess.STDOUT,
}


def get_child_process(proc_pid, expected_name, sub_test_name):
    if psutil is not None:
        # assuming pid has not been recycled/duplicated
        proc = psutil.Process(proc_pid)
        if proc.name() == "waypipe":
            for i in range(5):
                kids = proc.children()
                if len(kids) > 0:
                    break
                time.sleep(0.01)
            else:
                print(
                    "For test",
                    sub_test_name,
                    "waypipe server's command may have crashed",
                )
            if len(kids) == 1:
                wp_child = kids[0]
                try:
                    if wp_child.name() != expected_name:
                        print(
                            "Unusual child process name",
                            wp_child.name(),
                            "does not match",
                            expected_name,
                        )
                except psutil.NoSuchProcess:
                    pass


def open_logfile(name):
    path = os.path.join(xdg_runtime_dir, name)
    return path, open(path, "wb")


def start_waypipe(socket_path, control_path, logfile, command, oneshot):
    prefix = [waypipe_path, "--debug", "--socket", socket_path]
    if oneshot:
        prefix += ["--oneshot"]
    client_command = prefix + ["client"]
    server_command = prefix + ["--control", control_path, "server"] + command
    client = subprocess.Popen(client_command, stdout=logfile, **subproc_args)
    if not wait_until_exists(socket_path):
        raise Exception("The waypipe socket file at " + socket_path + " did not appear")
    server = subprocess.Popen(server_command, stdout=logfile, **wp_serv_args)
    return server, client


def cleanup_oneshot(client, server, child):
    if child is not None:
        try:
            child.send_signal(signal.SIGINT)
        except psutil.NoSuchProcess:
            time.sleep(0.1)
            safe_cleanup(server)
            time.sleep(0.1)
            safe_cleanup(client)
        else:
            server.wait()
            client.wait()
    else:
        safe_cleanup(server)
        time.sleep(0.1)
        safe_cleanup(client)
    return client.returncode, server.returncode


def cleanup_multi(client, server, child):
    if child is not None:
        try:
            child.send_signal(signal.SIGINT)
        except psutil.NoSuchProcess:
            pass
    time.sleep(0.1)
    safe_cleanup(server)
    time.sleep(0.1)
    safe_cleanup(client)
    return client.returncode, server.returncode


def run_sub_test(args):
    sub_test_name, command = args
    nontrivial_failures = False

    ocontrol_path = os.path.join(xdg_runtime_dir, sub_test_name + "_octrl")
    mcontrol_path = os.path.join(xdg_runtime_dir, sub_test_name + "_mctrl")
    owp_socket_path = os.path.join(xdg_runtime_dir, sub_test_name + "_osocket")
    mwp_socket_path = os.path.join(xdg_runtime_dir, sub_test_name + "_msocket")
    try_unlink(owp_socket_path)
    try_unlink(mwp_socket_path)
    try_unlink(ocontrol_path)
    try_unlink(mcontrol_path)

    ref_log_path, ref_out = open_logfile(sub_test_name + "_ref_out.txt")
    ref_proc = subprocess.Popen(command, stdout=ref_out, **subproc_args)

    owp_log_path, owp_out = open_logfile(sub_test_name + "_owp_out.txt")
    mwp_log_path, mwp_out = open_logfile(sub_test_name + "_mwp_out.txt")

    owp_server, owp_client = start_waypipe(
        owp_socket_path, ocontrol_path, owp_out, command, True
    )
    mwp_server, mwp_client = start_waypipe(
        mwp_socket_path, mcontrol_path, mwp_out, command, False
    )

    owp_child = get_child_process(
        owp_server.pid, os.path.basename(command[0]), sub_test_name
    )
    mwp_child = get_child_process(
        mwp_server.pid, os.path.basename(command[0]), sub_test_name
    )

    print("Launched", sub_test_name)

    time.sleep(1)

    # Verify that replacing the control pipe (albeit with itself) doesn't break anything
    # (Since the connection is a unix domain socket, almost no packets will be in flight,
    # so the test isn't that comprehensive)
    print("Resetting", sub_test_name)
    open(ocontrol_path, "w").write(owp_socket_path)
    open(mcontrol_path, "w").write(mwp_socket_path)
    try_unlink(ocontrol_path)
    try_unlink(mcontrol_path)

    time.sleep(1)

    print("Closing", sub_test_name)

    # Beware sudden PID reuse...
    safe_cleanup(ref_proc)
    ref_out.close()

    occode, oscode = cleanup_oneshot(owp_client, owp_server, owp_child)
    mccode, mscode = cleanup_multi(mwp_client, mwp_server, mwp_child)

    try_unlink(owp_socket_path)
    try_unlink(mwp_socket_path)
    owp_out.close()
    mwp_out.close()

    # -2, because applications sometimes return with the sigint error
    if ref_proc.returncode not in (0, -2):
        print(
            "Test {}, run directly, failed (code={}). See logfile at {}".format(
                sub_test_name, ref_proc.returncode, ref_log_path
            )
        )
    else:
        if oscode in (0, -2) and occode == 0:
            print("Oneshot test", sub_test_name, "passed")
        else:
            print(
                "Oneshot test {}, run indirectly, failed (ccode={} scode={}). See logfile at {}".format(
                    sub_test_name, occode, oscode, owp_log_path
                )
            )
            nontrivial_failures = True
        if mscode in (0, -2) and mccode in (0, -2):
            print("Regular test", sub_test_name, "passed")
        else:
            print(
                "Regular test {}, run indirectly, failed (ccode={} scode={}). See logfile at {}".format(
                    sub_test_name, mccode, mscode, mwp_log_path
                )
            )
            nontrivial_failures = True
    return nontrivial_failures


os.makedirs(xdg_runtime_dir, mode=0o700, exist_ok=True)
os.chmod(xdg_runtime_dir, 0o700)
try_unlink(abs_socket_path)
try_unlink(abs_socket_path + ".lock")

weston_log_path = os.path.join(xdg_runtime_dir, "weston_out.txt")
weston_out = open(weston_log_path, "wb")
weston_proc = subprocess.Popen(
    weston_command,
    env=mainenv,
    stdin=subprocess.DEVNULL,
    stdout=weston_out,
    stderr=subprocess.STDOUT,
)


# Otherwise it's a race between weston and the clients
if not wait_until_exists(abs_socket_path):
    raise Exception(
        "weston failed to create expected display socket path, " + abs_socket_path
    )

with multiprocessing.Pool(3) as pool:
    nontriv_failures = pool.map(run_sub_test, [(k, v) for k, v in sub_tests.items()])

safe_cleanup(weston_proc)
weston_out.close()
if weston_proc.returncode != 0:
    print("Running headless weston failed. See logfile at ", weston_log_path)

if any(nontriv_failures):
    quit(1)
quit(0)
