waypipe
================================================================================

waypipe is a proxy for Wayland[0] clients. It forwards Wayland messages and
serializes changes to shared memory buffers over a single socket. This makes
application forwarding similar to `ssh -X` [1] feasible.

[0] [https://wayland.freedesktop.org/](https://wayland.freedesktop.org/)
[1] [https://unix.stackexchange.com/questions/12755/how-to-forward-x-over-ssh-to-run-graphics-applications-remotely](https://unix.stackexchange.com/questions/12755/how-to-forward-x-over-ssh-to-run-graphics-applications-remotely)

## Usage

The invocation is currently somewhat complicated. Install `waypipe` on both
systems. Use absolute paths for `waypipe` and `weston-terminal`, since PATH
may not be the same on the remote system.

    SRV=localhost

    /usr/bin/waypipe -s /tmp/socket-local client &
    ssh -R/tmp/socket-remote:/tmp/socket-local -t $SRV \
        /usr/bin/waypipe -s /tmp/socket-remote server -- /usr/bin/weston-terminal
    
    kill %1

`waypipe` also provides a more abbreviated syntax for the above:

    /usr/bin/waypipe ssh $SRV /usr/bin/weston-terminal

## Installing

Build with meson[0]. Requirements:

* wayland (>= 1.15, to support absolute paths in WAYLAND_DISPLAY)
* scdoc (to generate a man page)
* ssh (OpenSSH >= 6.7, for Unix domain socket forwarding)

[0] [https://mesonbuild.com/](https://mesonbuild.com/)
[1] [https://git.sr.ht/~sircmpwn/scdoc](https://git.sr.ht/~sircmpwn/scdoc)

## Status

This is just a prototype right now.[0] The source code, command-line interface,
project name, primary branch, and git history may yet change completely. 

Any of the following will crash waypipe:

* Different local/client and remote/server versions
* Applications using non-shm-based protocols like linux_dmabuf
* Differing byte orders 

[0] [https://mstoeckl.com/notes/gsoc/blog.html](https://mstoeckl.com/notes/gsoc/blog.html)
