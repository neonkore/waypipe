#!/usr/bin/env python3

if __name__ != "__main__":
    quit(1)

import os, subprocess, time, signal, sys

if sys.version_info.minor < 4 or sys.version_info.major < 3:
    print("Python version is too old")
    quit(0)
import asyncio


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
            time.sleep(0.1)
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

xdg_runtime_dir = os.path.abspath("./test/")


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

try:
    import psutil
except ImportError:
    psutil = None

nontrivial_failures = False


@asyncio.coroutine
def run_sub_test(sub_test_name, command):
    global nontrivial_failures

    subenv = {
        "WAYLAND_DISPLAY": abs_socket_path,
        "WAYLAND_DEBUG": "1",
        "XDG_RUNTIME_DIR": xdg_runtime_dir,
        "LD_LIBRARY_PATH": ld_library_path,
    }

    wp_serv_env = {
        "WAYLAND_DEBUG": "1",
        "XDG_RUNTIME_DIR": xdg_runtime_dir,
        "LD_LIBRARY_PATH": ld_library_path,
    }

    subproc_args = {
        "env": subenv,
        "stdin": subprocess.DEVNULL,
        "stderr": subprocess.STDOUT,
    }

    wp_serv_args = {
        "env": wp_serv_env,
        "stdin": subprocess.DEVNULL,
        "stderr": subprocess.STDOUT,
    }

    ref_log_path = os.path.join(xdg_runtime_dir, sub_test_name + "_ref_out.txt")
    ref_out = open(ref_log_path, "wb")
    ref_proc = subprocess.Popen(command, stdout=ref_out, **subproc_args)

    wp_log_path = os.path.join(xdg_runtime_dir, sub_test_name + "_wp_out.txt")
    wp_out = open(wp_log_path, "wb")

    control_path = os.path.join(xdg_runtime_dir, sub_test_name + "_ctrl")
    wp_socket_path = os.path.join(xdg_runtime_dir, sub_test_name + "_socket")
    try_unlink(wp_socket_path)
    try_unlink(control_path)
    # '--oneshot', to make cleanup easier
    wp_prefix = [waypipe_path, "--debug", "--oneshot", "--socket", wp_socket_path]
    wp_client_command = wp_prefix + ["client"]
    wp_server_command = wp_prefix + ["--control", control_path, "server"] + command
    wp_client = subprocess.Popen(wp_client_command, stdout=wp_out, **subproc_args)
    if not wait_until_exists(wp_socket_path):
        raise Exception(
            "The waypipe socket file at " + wp_socket_path + " did not appear"
        )
    wp_server = subprocess.Popen(wp_server_command, stdout=wp_out, **wp_serv_args)

    wp_child = None
    if psutil is not None:
        # assuming pid has not been recycled/duplicated
        proc = psutil.Process(wp_server.pid)
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
                    if wp_child.name() != os.path.basename(command[0]):
                        print(
                            "Unusual child process name",
                            wp_child.name(),
                            "does not match",
                            command[0],
                        )
                except psutil.NoSuchProcess:
                    pass

    print("Launched", sub_test_name)
    yield from asyncio.sleep(1)
    # Verify that replacing the control pipe (albeit with itself) doesn't break anything
    # (Since the connection is a unix domain socket, almost no packets will be in flight,
    # so the test isn't that comprehensive)
    print("Resetting", sub_test_name)
    open(control_path, "w").write(wp_socket_path)
    try_unlink(control_path)
    yield from asyncio.sleep(1)
    print("Closing", sub_test_name)

    # Beware sudden PID reuse...
    safe_cleanup(ref_proc)
    ref_out.close()

    if wp_child is not None:
        try:
            wp_child.send_signal(signal.SIGINT)
        except psutil.NoSuchProcess:
            time.sleep(0.05)
            safe_cleanup(wp_server)
            time.sleep(0.05)
            safe_cleanup(wp_client)
        else:
            wp_server.wait()
            wp_client.wait()
    else:
        safe_cleanup(wp_server)
        time.sleep(0.05)
        safe_cleanup(wp_client)
    wp_out.close()
    try_unlink(wp_socket_path)

    # -2, because applications sometimes return with the sigint error
    if ref_proc.returncode not in (0, -2):
        print(
            "Test {}, run directly, failed (code={}). See logfile at {}".format(
                sub_test_name, ref_proc.returncode, ref_log_path
            )
        )
    else:
        if wp_server.returncode in (0, -2) and wp_client.returncode == 0:
            print("Test", sub_test_name, "passed")
        else:
            print(
                "Test {}, run indirectly, failed (ccode={} scode={}). See logfile at {}".format(
                    sub_test_name,
                    wp_client.returncode,
                    wp_server.returncode,
                    wp_log_path,
                )
            )
            nontrivial_failures = True


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

loop = asyncio.get_event_loop()
tasks = []
for k, v in sub_tests.items():
    tasks.append(asyncio.get_event_loop().create_task(run_sub_test(k, v)))
loop.run_until_complete(asyncio.gather(*tasks))

safe_cleanup(weston_proc)
weston_out.close()
if weston_proc.returncode != 0:
    print("Running headless weston failed. See logfile at ", weston_log_path)

if nontrivial_failures:
    quit(1)
quit(0)
