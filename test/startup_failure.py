#!/usr/bin/python3

"""
Verifying all the ways in which waypipe can fail before even making a connection.
"""

if __name__ != "__main__":
    quit(1)

import os, subprocess, time, signal, socket


def try_unlink(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


waypipe_path = os.environ["TEST_WAYPIPE_PATH"]
ld_library_path = (
    os.environ["LD_LIBRARY_PATH"] if "LD_LIBRARY_PATH" in os.environ else ""
)

xdg_runtime_dir = os.path.abspath("./test_startup_failure")
os.makedirs(xdg_runtime_dir, mode=0o700, exist_ok=True)
os.chmod(xdg_runtime_dir, 0o700)

all_succeeding = True

client_socket_path = xdg_runtime_dir + "/socket-client"
server_socket_path = xdg_runtime_dir + "/socket-server"
wayland_display_path = xdg_runtime_dir + "/socket-wayland-display"

try_unlink(wayland_display_path)
display_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
display_socket.bind(wayland_display_path)
display_socket.listen()


def run_test(name, command, env, use_socketpair, expect_success):
    try_unlink(client_socket_path)
    try_unlink(server_socket_path)
    try_unlink(server_socket_path + ".disp.sock")
    if use_socketpair:
        sockets = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        conn_socket = os.dup2(sockets[1].fileno(), 999, inheritable=True)
        env = dict(env, WAYLAND_SOCKET=str(conn_socket))
        pfds = [conn_socket]
    else:
        pfds = []

    timed_out = False
    try:
        proc = subprocess.run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=0.25,
            pass_fds=pfds,
        )
    except subprocess.TimeoutExpired as e:
        timed_out = True
        output = e.output
        # Program began to wait for a connection
        retcode = 0 if "client" in command else (0 if expect_success else 1)
    else:
        output = proc.stdout
        retcode = proc.returncode

    if use_socketpair:
        os.close(conn_socket)

    log_path = os.path.join(xdg_runtime_dir, "weston_out.txt")
    with open(log_path, "wb") as out:
        out.write(output)

    global all_succeeding
    failed = retcode != 0 or timed_out == False
    if expect_success:
        if failed:
            print(
                "Run {} failed when it should have succeeded".format(name),
                output,
                retcode,
                "timeout" if timed_out else "notimeout",
            )
            all_succeeding = False
        else:
            print("Run {} passed.".format(name), output)
    else:
        if not failed:
            print(
                "Run {} succeeded when it should have failed".format(name),
                output,
                retcode,
                "timeout" if timed_out else "notimeout",
            )
            all_succeeding = False
        else:
            print("Run {} passed:".format(name), output)


base_env = {"LD_LIBRARY_PATH": ld_library_path}
standard_env = dict(base_env, XDG_RUNTIME_DIR=xdg_runtime_dir)
# Configurations that should fail
run_test(
    "b_client_long_disp",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_DISPLAY=("/" + "x" * 107)),
    False,
    False,
)
run_test(
    "b_client_disp_dne",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_DISPLAY=xdg_runtime_dir + "/dne"),
    False,
    False,
)
run_test(
    "b_client_no_env",
    [waypipe_path, "-s", client_socket_path, "client"],
    base_env,
    False,
    False,
)
run_test(
    "b_server_oneshot_no_env",
    [waypipe_path, "-o", "-s", server_socket_path, "server", "sleep", "0.26"],
    base_env,
    False,
    False,
)
run_test(
    "b_client_bad_pipe1",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_SOCKET="33"),
    False,
    False,
)
run_test(
    "b_client_bad_pipe2",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_SOCKET="777777777777777777777777777"),
    False,
    False,
)
run_test(
    "b_client_bad_pipe3",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_SOCKET="0x33"),
    False,
    False,
)
run_test(
    "b_client_nxdg_offset",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_DISPLAY="socket-wayland-display"),
    False,
    False,
)

# Configurations that should succeed
run_test(
    "g_server_no_env",
    [waypipe_path, "-s", server_socket_path, "server", "sleep", "0.26"],
    base_env,
    False,
    True,
)
run_test(
    "g_client_std_env",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(standard_env, WAYLAND_DISPLAY=wayland_display_path),
    False,
    True,
)
run_test(
    "g_client_offset_sock",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(standard_env, WAYLAND_DISPLAY="socket-wayland-display"),
    False,
    True,
)
run_test(
    "g_client_pipe_env",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(standard_env),
    True,
    True,
)

quit(0 if all_succeeding else 1)
