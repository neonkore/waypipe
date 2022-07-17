#!/usr/bin/env python3

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


def make_socket(path):
    folder, filename = os.path.split(path)
    cwdir = os.open(".", os.O_RDONLY | os.O_DIRECTORY)

    display_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    os.chdir(folder)
    display_socket.bind(filename)
    display_socket.listen()
    os.fchdir(cwdir)
    os.close(cwdir)

    return display_socket


waypipe_path = os.environ["TEST_WAYPIPE_PATH"]
sleep_path = os.environ["TEST_SLEEP_PATH"]
fake_ssh_path = os.environ["TEST_FAKE_SSH_PATH"]
ld_library_path = (
    os.environ["LD_LIBRARY_PATH"] if "LD_LIBRARY_PATH" in os.environ else ""
)

xdg_runtime_dir = os.path.abspath("./run/")
os.makedirs(xdg_runtime_dir, mode=0o700, exist_ok=True)
os.chmod(xdg_runtime_dir, 0o700)

all_succeeding = True

wayland_display = "wayland-display"
client_socket_path = xdg_runtime_dir + "/client-socket"
server_socket_path = xdg_runtime_dir + "/server-socket"
ssh_socket_path = xdg_runtime_dir + "/ssh-socket"
wayland_display_path = xdg_runtime_dir + "/" + wayland_display

try_unlink(wayland_display_path)
display_socket = make_socket(wayland_display_path)

USE_SOCKETPAIR = 1 << 1
EXPECT_SUCCESS = 1 << 2
EXPECT_TIMEOUT = 1 << 3
EXPECT_FAILURE = 1 << 4


def run_test(name, command, env, flags):
    try_unlink(client_socket_path)
    try_unlink(server_socket_path)
    try_unlink(server_socket_path + ".disp.sock")
    if flags & USE_SOCKETPAIR:
        sockets = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        conn_socket = 999
        os.dup2(sockets[1].fileno(), conn_socket, inheritable=True)
        env = dict(env, WAYLAND_SOCKET=str(conn_socket))
        pfds = [conn_socket]
    else:
        pfds = []

    timed_out = False
    log_path = os.path.join(xdg_runtime_dir, "sfail_{}.txt".format(name))
    logfile = open(log_path, "wb")
    print(env, " ".join(command))

    proc = subprocess.Popen(
        command,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=logfile,
        stderr=subprocess.STDOUT,
        pass_fds=pfds,
        start_new_session=True,
    )
    try:
        output, none = proc.communicate(timeout=1.0)
    except subprocess.TimeoutExpired as e:
        # Program is waiting indefinitely for something.
        # Kill it, and all children.
        pgrp = os.getpgid(proc.pid)
        os.killpg(pgrp, signal.SIGKILL)
        retcode = None
        timed_out = True
    else:
        retcode = proc.returncode

    logfile.close()
    output = open(log_path, "rb").read()

    if flags & USE_SOCKETPAIR:
        os.close(conn_socket)

    log_path = os.path.join(xdg_runtime_dir, "weston_out.txt")
    with open(log_path, "wb") as out:
        out.write(output)

    result = (
        "timeout"
        if timed_out
        else ("fail({})".format(retcode) if retcode != 0 else "pass")
    )

    global all_succeeding
    if flags & EXPECT_SUCCESS:
        if timed_out or retcode != 0:
            print(
                "Run {} failed when it should have succeeded".format(name),
                output,
                retcode,
                "timeout" if timed_out else "notimeout",
            )
            all_succeeding = False
        else:
            print("Run {} passed.".format(name), output)
    elif flags & EXPECT_FAILURE:
        if timed_out or retcode == 0:
            print(
                "Run {} succeeded when it should have failed".format(name),
                output,
                retcode,
                "timeout" if timed_out else "notimeout",
            )
            all_succeeding = False
        else:
            print("Run {} passed.".format(name), output)
    elif flags & EXPECT_TIMEOUT:
        if not timed_out:
            print(
                "Run {} stopped when it should have continued".format(name),
                output,
                retcode,
            )
            all_succeeding = False
        else:
            print("Run {} passed.".format(name), output)
    else:
        raise NotImplementedError


wait_cmd = [sleep_path, "10.0"]
invalid_hostname = "@"
fake_ssh_dir = os.path.dirname(fake_ssh_path)
waypipe_dir = os.path.dirname(waypipe_path)

base_env = {"LD_LIBRARY_PATH": ld_library_path, "PATH": ""}
standard_env = dict(base_env, XDG_RUNTIME_DIR=xdg_runtime_dir)
ssh_only_env = dict(standard_env, PATH=fake_ssh_dir)
ssh_env = dict(standard_env, PATH=fake_ssh_dir + ":" + waypipe_dir)
# Configurations that should fail
run_test(
    "b_client_long_disp",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_DISPLAY=("/" + "x" * 107)),
    EXPECT_FAILURE,
)
run_test(
    "b_client_disp_dne",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_DISPLAY=xdg_runtime_dir + "/dne"),
    EXPECT_FAILURE,
)
run_test(
    "b_client_no_env",
    [waypipe_path, "-s", client_socket_path, "client"],
    base_env,
    EXPECT_FAILURE,
)
run_test(
    "b_server_oneshot_no_env",
    [waypipe_path, "-o", "-s", server_socket_path, "server"] + wait_cmd,
    base_env,
    EXPECT_TIMEOUT,
)
run_test(
    "b_client_bad_pipe1",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_SOCKET="33"),
    EXPECT_FAILURE,
)
run_test(
    "b_client_bad_pipe2",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_SOCKET="777777777777777777777777777"),
    EXPECT_FAILURE,
)
run_test(
    "b_client_bad_pipe3",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_SOCKET="0x33"),
    EXPECT_FAILURE,
)
run_test(
    "b_client_nxdg_offset",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(base_env, WAYLAND_DISPLAY=wayland_display),
    EXPECT_FAILURE,
)
run_test(
    "b_server_no_env",
    [waypipe_path, "-s", server_socket_path, "server"] + wait_cmd,
    base_env,
    EXPECT_FAILURE,
)
run_test(
    "g_ssh_test_nossh_env",
    [waypipe_path, "-o", "-s", ssh_socket_path, "ssh", invalid_hostname] + wait_cmd,
    dict(standard_env, WAYLAND_DISPLAY=wayland_display),
    EXPECT_FAILURE,
)


# Configurations that should succeed
run_test(
    "g_help",
    [waypipe_path, "--help"],
    base_env,
    EXPECT_SUCCESS,
)
run_test(
    "g_server_std_env",
    [waypipe_path, "-s", server_socket_path, "server"] + wait_cmd,
    standard_env,
    EXPECT_TIMEOUT,
)
run_test(
    "g_client_std_env",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(standard_env, WAYLAND_DISPLAY=wayland_display_path),
    EXPECT_TIMEOUT,
)
run_test(
    "g_client_offset_sock",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(standard_env, WAYLAND_DISPLAY=wayland_display),
    EXPECT_TIMEOUT,
)
run_test(
    "g_client_pipe_env",
    [waypipe_path, "-s", client_socket_path, "client"],
    dict(standard_env),
    EXPECT_TIMEOUT | USE_SOCKETPAIR,
)
run_test(
    "g_ssh_test_oneshot",
    [waypipe_path, "-o", "-s", ssh_socket_path, "ssh", invalid_hostname] + wait_cmd,
    dict(ssh_env, WAYLAND_DISPLAY=wayland_display),
    EXPECT_TIMEOUT,
)
run_test(
    "g_ssh_test_reg",
    [waypipe_path, "-s", ssh_socket_path, "ssh", invalid_hostname] + wait_cmd,
    dict(ssh_env, WAYLAND_DISPLAY=wayland_display),
    EXPECT_TIMEOUT,
)
run_test(
    "g_ssh_test_remotebin",
    [
        waypipe_path,
        "--oneshot",
        "--remote-bin",
        waypipe_path,
        "-s",
        ssh_socket_path,
        "ssh",
        invalid_hostname,
    ]
    + wait_cmd,
    dict(ssh_only_env, WAYLAND_DISPLAY=wayland_display),
    EXPECT_TIMEOUT,
)

try_unlink(client_socket_path)
try_unlink(wayland_display_path)
quit(0 if all_succeeding else 1)
