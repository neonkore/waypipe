#!/usr/bin/env python3

import sys, os, subprocess, shutil

"""
Script to check that Waypipe builds and that tests pass in all of
its configurations.
"""

waypipe_root, build_root = sys.argv[1], sys.argv[2]
os.makedirs(build_root, exist_ok=True)

setups = [
    ("regular", ["--buildtype", "debugoptimized"], {}),
    ("release", ["--buildtype", "release"], {}),
    ("clang", ["--buildtype", "debugoptimized"], {"CC": "clang"}),
    (
        "clang-tsan",
        ["--buildtype", "debugoptimized", "-Db_sanitize=thread"],
        {"CC": "clang"},
    ),
    (
        "clang-asan",
        ["--buildtype", "debugoptimized", "-Db_sanitize=address,undefined"],
        {"CC": "clang"},
    ),
    (
        "empty",
        [
            "--buildtype",
            "debugoptimized",
            "-Dwith_video=disabled",
            "-Dwith_lz4=disabled",
            "-Dwith_zstd=disabled",
            "-Dwith_dmabuf=disabled",
        ],
        {"CC": "gcc"},
    ),
    (
        "novideo",
        [
            "--buildtype",
            "debugoptimized",
            "-Dwith_video=disabled",
        ],
        {"CC": "gcc"},
    ),
    (
        "nolz4",
        [
            "--buildtype",
            "debugoptimized",
            "-Dwith_lz4=disabled",
        ],
        {"CC": "gcc"},
    ),
    (
        "unity",
        ["--buildtype", "debugoptimized", "--unity", "on", "--unity-size", "400"],
        {"CC": "gcc", "CFLAGS": "-pedantic -D_GNU_SOURCE"},
    ),
    (
        "error",
        ["--buildtype", "debugoptimized"],
        {"CC": "gcc", "CFLAGS": "-Wunused-result -std=c11 -pedantic -ggdb3 -O1"},
    ),
]
main_options = ["video", "dmabuf", "lz4", "zstd", "vaapi"]
bool_map = {True: "enabled", False: "disabled"}
for compiler in ["gcc", "clang"]:
    for flags in range(2 ** len(main_options)):
        bool_options = [(2**i) & flags != 0 for i in range(len(main_options))]
        name = "-".join(
            ["poly", compiler] + [m for m, b in zip(main_options, bool_options) if b]
        )
        flag_values = [
            "-Dwith_{}={}".format(m, bool_map[b])
            for m, b in zip(main_options, bool_options)
        ]
        setups.append(
            (name, ["--buildtype", "debugoptimized"] + flag_values, {"CC": compiler})
        )

if len(sys.argv) >= 4:
    setups = [(s, c, e) for s, c, e in setups if s == sys.argv[3]]

base_env = os.environ.copy()
for key, options, env in setups:
    print(key, end=" ")
    sys.stdout.flush()
    nenv = base_env.copy()
    for e in env:
        nenv[e] = env[e]

    bdir = os.path.join(build_root, key)
    try:
        shutil.rmtree(bdir)
    except FileNotFoundError:
        pass
    r1 = subprocess.run(
        ["meson", waypipe_root, bdir] + options, capture_output=True, env=nenv
    )
    if r1.returncode:
        print("failed")
        print(r1.stdout, r1.stderr, r1.returncode)
        continue
    r2 = subprocess.run(["ninja", "test"], cwd=bdir, capture_output=True, env=nenv)
    if r2.returncode:
        print("failed")
        print(r2.stdout, r2.stderr, r2.returncode)
        continue
    print("passed")
