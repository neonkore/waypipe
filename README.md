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

This program is now relatively stable, with no large changes to the
command line interface or wire format expected. Features like video
encoding, multiplanar and tiled DMABUFs, and support for newer Wayland
protocols are less well tested and more likely to break between minor
versions.

Waypipe is developed at [1]; file bug reports or submit patches here.

The wire format most recently changed with version 0.7.0, and is not
compatible with earlier versions of Waypipe. Both the client and
server sides of a connection must have a feature in order for it to work;
for example, if the local copy of Waypipe was built without LZ4 support,
and the remote copy has the `--compress lz4` option set, the connection
may fail at some point.

Any of the following may make waypipe crash with an error message. If
it segfaults, file a bug report!

* Different local/client and remote/server versions or capabilities
* Differing byte orders
* Applications using unexpected protocols that pass file descriptors; file
  bug reports for these

[0] [https://mstoeckl.com/notes/gsoc/blog.html](https://mstoeckl.com/notes/gsoc/blog.html)
[1] [https://gitlab.freedesktop.org/mstoeckl/waypipe/](https://gitlab.freedesktop.org/mstoeckl/waypipe/)

## Limitations

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
