waypipe
================================================================================

`waypipe` is a proxy for Wayland[0] clients. It forwards Wayland messages and
serializes changes to shared memory buffers over a single socket. This makes
application forwarding similar to `ssh -X` [1] feasible.

[0] [https://wayland.freedesktop.org/](https://wayland.freedesktop.org/)
[1] [https://unix.stackexchange.com/questions/12755/how-to-forward-x-over-ssh-to-run-graphics-applications-remotely](https://unix.stackexchange.com/questions/12755/how-to-forward-x-over-ssh-to-run-graphics-applications-remotely)

## Usage

`waypipe` should be installed on both the local and remote computers. There is
a user-friendly command line pattern which prefixes a call to `ssh` and
automatically sets up a reverse tunnel for protocol data. For example,

    waypipe ssh -C user@theserver weston-terminal

will run `ssh`, connect to `theserver`, and remotely run `weston-terminal`,
using local and remote `waypipe` processes to synchronize the shared memory
buffers used by Wayland clients between both computers. Command line arguments
before `ssh` apply only to `waypipe`; those after `ssh` belong to `ssh`.

Alternatively, one can set up the local and remote processes by hand, with the
following set of shell commands:

    /usr/bin/waypipe -s /tmp/socket-local client &
    ssh -R /tmp/socket-remote:/tmp/socket-local -t user@theserver \
        /usr/bin/waypipe -s /tmp/socket-remote server -- \
        /usr/bin/weston-terminal
    kill %1

## Installing

Build with meson[0]. A typical incantation is

    cd /path/to/waypipe/..
    mkdir build-waypipe
    meson --buildtype debugoptimized waypipe build-waypipe
    ninja -C build-waypipe install

Requirements:

* meson (>= 0.46 or possibly earlier. a backend for it (i.e, ninja) is
  also needed)
* wayland (>= 1.15, to support absolute paths in WAYLAND_DISPLAY)
* wayland-protocols (>= 1.12, for the xdg-shell protocol, and others)
* libffi
* libgbm (from a recent version of mesa)
* scdoc (optional, to generate a man page)
* sys/sdt.h (optional, to provide static tracepoints for profiling)
* ssh (runtime, OpenSSH >= 6.7, for Unix domain socket forwarding)

[0] [https://mesonbuild.com/](https://mesonbuild.com/)
[1] [https://git.sr.ht/~sircmpwn/scdoc](https://git.sr.ht/~sircmpwn/scdoc)

## Status

This is just a prototype right now[0]. The source code[1], command-line
interface, project name, primary branch, and git history may yet change
completely. Bug reports and patches are always welcome.

Any of the following will crash waypipe:

* Different local/client and remote/server versions
* Applications using unexpected protocols that pass file descriptors
* Differing byte orders

[0] [https://mstoeckl.com/notes/gsoc/blog.html](https://mstoeckl.com/notes/gsoc/blog.html)
[1] [https://gitlab.freedesktop.org/mstoeckl/waypipe/](https://gitlab.freedesktop.org/mstoeckl/waypipe/)
