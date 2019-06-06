waypipe(1)

# NAME

waypipe - A transparent proxy for Wayland applications

# SYNOPSIS

*waypipe* [options...] client++
*waypipe* [options...] server -- command++
*waypipe* [options...] ssh ...

# DESCRIPTION

waypipe is a proxy for Wayland clients, with the aim of supporting behavior
like *ssh -X*.

# OPTIONS

*-d, --debug*
	Print debug log messages.

*-h, --help*
	Show help message and quit.

*-n, --no-gpu*
	Block protocols like wayland-drm and linux-dmabuf which require access
	to e.g. render nodes.

*-o, --oneshot*
	Only permit a single connection, and exit when it is closed.

*-s S, --socket S*
	Use *S* as the path for the Unix socket. The default socket path for
	server mode is _/tmp/waypipe-server.sock_; for client mode, it is
	_/tmp/waypipe-client.sock_; and in ssh mode, *S* gives the prefix used by
	both the client and the server for their socket paths.

*-v, --version*
	Print the version number and quit.

*--unlink-socket*
	Only for server mode; on shutdown, unlink the Unix socket that waypipe connects to.

*--login-shell*
	Only for server mode; if no command is being run, open a login shell.

*--drm-node R*
	Specify the path *R* to the drm device that this instance of waypipe should
	use and (in server mode) notify connecting applications about.

*--remote-node R*
	In ssh mode, specify the path *R* to the drm device that the remote instance
	of waypipe (running in server mode) should use.

# EXAMPLE 

The following *waypipe ssh* subcommand will attempt to run *weston-flower* on
the server _exserv_, displaying the result on the local system.

```
	waypipe ssh user@exserv weston-flower
```

One can obtain similar behavior by explictly running waypipe and ssh:

```
	waypipe --socket /tmp/socket-client client  &
	ssh -R/tmp/socket-server:/tmp/socket-client -t user@exserv \
		waypipe --socket /tmp/socket-server server -- weston-flower
	kill %1
```

Waypipe may be run locally without an ssh connection by specifying matching
socket paths. For example:

```
	waypipe --socket /tmp/waypipe.sock client &
	waypipe --socket /tmp/waypipe.sock server weston-simple-dmabuf-egl
	kill %1
	rm /tmp/waypipe.sock
```

# ENVIRONMENT

When running as a server, by default _WAYLAND_DISPLAY_ will be set for the
invoked process. If the *--oneshot* flag is set, waypipe will instead set
_WAYLAND_SOCKET_ and inherit a corresponding file descriptor to the invoked
(child) process.

# SEE ALSO

*weston*(1)
