Waypipe
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

    waypipe ssh user@theserver weston-terminal

will run `ssh`, connect to `theserver`, and remotely run `weston-terminal`,
using local and remote `waypipe` processes to synchronize the shared memory
buffers used by Wayland clients between both computers. Command line arguments
before `ssh` apply only to `waypipe`; those after `ssh` belong to `ssh`.

Alternatively, one can launch the local and remote processes by hand, with the
following set of shell commands:

    /usr/bin/waypipe -s /tmp/socket-local client &
    ssh -R /tmp/socket-remote:/tmp/socket-local -t user@theserver \
        /usr/bin/waypipe -s /tmp/socket-remote server -- \
        /usr/bin/weston-terminal
    kill %1

It's possible to set up the local and remote processes so that, when the
connection between the the sockets used by each end breaks, one can create
a new forwarded socket on the remote side and reconnect the two processes.
For a more detailed example, see the man page.

## Installing

Build with meson[0]. A typical incantation is

    cd /path/to/waypipe/ && cd ..
    mkdir build-waypipe
    meson --buildtype debugoptimized waypipe build-waypipe
    ninja -C build-waypipe install

Core build requirements:

* meson (build, >= 0.47. with dependencies `ninja`, `pkg-config`, `python3`)
* C compiler

Optional dependencies:

* liblz4 (for fast compression, >=1.7.0)
* libzstd (for slower compression, >= 0.4.6)
* libgbm (to support programs using OpenGL via DMABUFs)
* libdrm (same as for libgbm)
* ffmpeg (>=3.1, needs avcodec/avutil/swscale for lossy video encoding)
* libva (for hardware video encoding and decoding)
* scdoc (to generate a man page)
* sys/sdt.h (to provide static tracepoints for profiling)
* ssh (runtime, OpenSSH >= 6.7, for Unix domain socket forwarding)
* libx264 (ffmpeg runtime, for software video decoding and encoding)

[0] [https://mesonbuild.com/](https://mesonbuild.com/)
[1] [https://git.sr.ht/~sircmpwn/scdoc](https://git.sr.ht/~sircmpwn/scdoc)

## Status

This is usable, but still somewhat unstable right now[0]. The main
development location[1], command-line interface, and wire format may yet
change completely. Bug reports and patches are always welcome.

The wire format most recently changed with version 0.7.0, and is not
compatible with earlier versions of Waypipe.

Any of the following may make waypipe crash with an error message. If
it segfaults, file a bug report!

* Different local/client and remote/server versions
* Differing byte orders
* Applications using unexpected protocols that pass file descriptors; file
  bug reports for these

[0] [https://mstoeckl.com/notes/gsoc/blog.html](https://mstoeckl.com/notes/gsoc/blog.html)
[1] [https://gitlab.freedesktop.org/mstoeckl/waypipe/](https://gitlab.freedesktop.org/mstoeckl/waypipe/)
