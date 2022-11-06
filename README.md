Waypipe
================================================================================

`waypipe` is a proxy for Wayland[0] clients. It forwards Wayland messages and
serializes changes to shared memory buffers over a single socket. This makes
application forwarding similar to `ssh -X` [1] feasible.

[0] [https://wayland.freedesktop.org/](https://wayland.freedesktop.org/)
[1] [https://wiki.archlinux.org/title/OpenSSH#X11_forwarding](https://wiki.archlinux.org/title/OpenSSH#X11_forwarding)

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

## Reporting issues

Waypipe is developed at [0]; file bug reports or submit patches here.

In general, if a program does not work properly under Waypipe, it is a bug
worth reporting. If possible, before doing so ensure both computers are using
the most recently released version of Waypipe (or are built from git master).

A workaround that may help for some programs using OpenGL or Vulkan is to
run Waypipe with the `--no-gpu` flag, which may force them to use software
rendering and shared memory buffers. (Please still file a bug.)

Some programs may require specific environment variable settings or command
line flags to run remotely; a few examples are given in the man page[1]. 

Useful information for bug reports includes:

* If a Waypipe process has crashed on either end of the connection,
  a full stack trace, with debug symbols. (In gdb, `bt full`).
* If the program uses OpenGL or Vulkan, the graphics cards and drivers on
  both computers.
* The output of `waypipe --version` on both ends of the connection
* Logs when Waypipe is run with the `--debug` flag, or when the program
  is run with the environment variable setting `WAYLAND_DEBUG=1`.
* Screenshots of any visual glitches.

[0] [https://gitlab.freedesktop.org/mstoeckl/waypipe/](https://gitlab.freedesktop.org/mstoeckl/waypipe/)
[1] [https://gitlab.freedesktop.org/mstoeckl/waypipe/-/blob/master/waypipe.scd](https://gitlab.freedesktop.org/mstoeckl/waypipe/-/blob/master/waypipe.scd)

## Technical Limitations

Waypipe does not have a full view of the Wayland protocol. It includes a
compiled form of the base protocol and several extension protocols, but is not
able to parse all messages that the programs it connects send. Fortunately, the
Wayland wire protocol is partially self-describing, so Waypipe can parse the
messages it needs (those related to resources shared with file descriptors)
while ignoring the rest. This makes Waypipe partially forward-compatible: if a
future protocol comes out about details (for example, about window positioning)
which do not require that file descriptors be sent, then applications will be
able to use that protocol even with older versions of Waypipe. The
tradeoff to allowing messages that Waypipe can not parse is that Waypipe can
only make minor modifications to the wire protocol. In particular, adding or
removing any Wayland protocol objects would require changing all messages that
refer to them, including those messages that Waypipe does not parse. This
precludes, for example, global object deduplication tricks that could reduce
startup time for complicated applications.

Shared memory buffer updates, including those for the contents of windows, are
tracked by keeping a "mirror" copy of the buffer the represents the view which
the opposing instance of Waypipe has. This way, Waypipe can send only the
regions of the buffer that have changed relative to the remote copy. This is
more efficient than resending the entire buffer on every update, which is good
for applications with reasonably static user interfaces (like a text editor or
email client). However, with programs with animations where the interaction
latency matters (like games or certain audio tools), major window updates will
unavoidably produce a lag spike. The additional memory cost of keeping mirrors
is moderate.

The video encoding option for DMABUFs currently maintains a video stream for
each buffer that is used by a window surface. Since surfaces typically rotate
between a small number of buffers, a video encoded window will appear to
flicker as it switches rapidly between the underlying buffers, each of whose
video streams has different encoding artifacts.

The `zwp_linux_explicit_synchronization_v1` Wayland protocol is currently not
supported.

Waypipe does not work between computers that use different byte orders.
