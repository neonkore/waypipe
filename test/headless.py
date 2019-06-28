#!/usr/bin/python3

if __name__ != "__main__":
    quit(1)

import os, subprocess, time, signal


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
            time.sleep(0.01)
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
weston_shm_path = os.environ["TEST_WESTON_SHM_PATH"]
weston_egl_path = os.environ["TEST_WESTON_EGL_PATH"]
weston_dma_path = os.environ["TEST_WESTON_DMA_PATH"]
waypipe_path = os.environ["TEST_WAYPIPE_PATH"]
ld_library_path = (
    os.environ["LD_LIBRARY_PATH"] if "LD_LIBRARY_PATH" in os.environ else ""
)

xdg_runtime_dir = os.path.abspath("./test/")
os.makedirs(xdg_runtime_dir, mode=0o700, exist_ok=True)
os.chmod(xdg_runtime_dir, 0o700)

# weston does not currently appear to support setting absolute socket paths
socket_path = "w_sock"
abs_socket_path = os.path.join(xdg_runtime_dir, socket_path)
try_unlink(abs_socket_path)
try_unlink(abs_socket_path + ".lock")

mainenv = {"XDG_RUNTIME_DIR": xdg_runtime_dir, "LD_LIBRARY_PATH": ld_library_path}

weston_command = [
    weston_path,
    "--backend=headless-backend.so",
    "--socket=" + socket_path,
    # "--use-pixman",
    "--width=-2000",
    "--height=2000",
]

weston_log_path = os.path.join(xdg_runtime_dir, "weston_out.txt")
weston_out = open(weston_log_path, "wb")
weston_proc = subprocess.Popen(
    weston_command,
    env=mainenv,
    stdin=subprocess.DEVNULL,
    stdout=weston_out,
    stderr=subprocess.STDOUT,
)

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

subproc_args = {"env": subenv, "stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT}

wp_serv_args = {
    "env": wp_serv_env,
    "stdin": subprocess.DEVNULL,
    "stderr": subprocess.STDOUT,
}

# Otherwise it's a race between weston and the clients
if not wait_until_exists(abs_socket_path):
    raise Exception(
        "weston failed to create expected display socket path, " + abs_socket_path
    )

sub_tests = {
    "SHM": [weston_shm_path],
    "EGL": [weston_egl_path, "-o"],
    "DMABUF": [weston_dma_path],
}

processes = {}

try:
    import psutil
except ImportError:
    psutil = None

for sub_test_name, command in sub_tests.items():
    ref_log_path = os.path.join(xdg_runtime_dir, sub_test_name + "_ref_out.txt")
    ref_out = open(ref_log_path, "wb")
    ref_proc = subprocess.Popen(command, stdout=ref_out, **subproc_args)

    wp_log_path = os.path.join(xdg_runtime_dir, sub_test_name + "_wp_out.txt")
    wp_out = open(wp_log_path, "wb")

    wp_socket_path = os.path.join(xdg_runtime_dir, sub_test_name + "_socket")
    try_unlink(wp_socket_path)
    wp_prefix = [waypipe_path, "--debug", "--oneshot", "--socket", wp_socket_path]
    wp_client_command = wp_prefix + ["client"]
    wp_server_command = wp_prefix + ["server"] + command
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
                if wp_child.name() != os.path.basename(command[0]):
                    print(
                        "Unusual child process name",
                        wp_child.name(),
                        "does not match",
                        command[0],
                    )

    processes[sub_test_name] = (
        ref_proc,
        ref_out,
        ref_log_path,
        wp_client,
        wp_server,
        wp_child,
        wp_out,
        wp_log_path,
    )

time.sleep(0.5)

# i.e., did running the program directly work, but via waypipe fail ?
nontrivial_failures = False

for sub_test_name, bundle in processes.items():
    (
        ref_proc,
        ref_out,
        ref_log_path,
        wp_client,
        wp_server,
        wp_child,
        wp_out,
        wp_log_path,
    ) = bundle

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

safe_cleanup(weston_proc)
weston_out.close()
if weston_proc.returncode != 0:
    print("Running headless weston failed. See logfile at ", weston_log_path)

if nontrivial_failures:
    quit(1)
quit(0)
