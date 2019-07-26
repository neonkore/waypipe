waypipe(1)

# NAME

waypipe - A transparent proxy for Wayland applications

# SYNOPSIS

*waypipe* [options...] client++
*waypipe* [options...] server -- _command..._++
*waypipe* [options...] recon _control_pipe_ _new_socket_path_++
*waypipe* [options...] ssh ...

# DESCRIPTION

waypipe is a proxy for Wayland clients, with the aim of supporting behavior
like *ssh -X*.

When run as *waypipe client*, it will open a socket (by default at
_/tmp/waypipe-client.sock_) and will connect to the local Wayland compositor
and forward all Wayland applications which were linked to it over the socket
by a matching *waypipe server* instance.

When run as *waypipe server*, it will run the command that follows in its
command line invocation, set up its own Wayland compositor socket, and
try to connect to its matching *waypipe client* socket (by default
_/tmp/waypipe-server.sock_) and try to forward all the Wayland clients
that connect to fake compositor socket to the matching *waypipe client*.

The *waypipe recon* mode is used to reconnect a *waypipe server* instance
which has had a control pipe (option *--control*) set. The new socket path
should indicate a Unix socket whose connections are forwarded to the *waypipe
client* that the *waypipe server* was initially connected to.

Finally, prefixing an *ssh ...* command to become *waypipe ssh ...* will
automatically set up local and remote copies of *waypipe*, as well as
forwarding between their sockets, so that Wayland applications run remotely
will be displayed locally.

# OPTIONS

*-c C, --compress C*
	Select the compression method applied to data transfers. Options are
	_none_ (for high-bandwidth networks), _lz4_ (intermediate), _zstd_
	(slow connection). The default compression is _none_.

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

*--control C*
	For server or ssh mode, provide the path to the "control pipe" that will
	be created the the server. Writing (with *waypipe recon C T*, or
	'echo -n T > C') a new socket path to this pipe will make the server
	instance replace all running connections with connections to the new
	Unix socket. The new socket should ultimately forward data to the same
	waypipe client that the server was connected to before.

*--display D*
	For server or ssh mode, provide _WAYLAND_DISPLAY_ and let waypipe configure
	its Wayland display socket to have a matching path. (If *D* is not an
	absolute path, the socket will be created in the folder given by the
	environment variable _XDG_RUNTIME_DIR_.)

*--drm-node R*
	Specify the path *R* to the drm device that this instance of waypipe should
	use and (in server mode) notify connecting applications about.

*--remote-node R*
	In ssh mode, specify the path *R* to the drm device that the remote instance
	of waypipe (running in server mode) should use.

*--linear-dmabuf*
	Filter out all advertised DMABUF formats which have modifiers; only standard
	linear image layouts are then permitted. Some applications by default use
	DMABUF image layout modifiers which are very slow for waypipe to copy
	and update; this flag can ensure that they fall back to friendlier formats.

*--login-shell*
	Only for server mode; if no command is being run, open a login shell.

*--threads T*
	Set the number of total threads (including the main thread) which a *waypipe*
	instance will create. These threads will be used to parallelize compression
	operations. This flag is passed on to *waypipe server* when given to *waypipe
	ssh*.

*--unlink-socket*
	Only for server mode; on shutdown, unlink the Unix socket that waypipe connects to.

*--video*
	Compress specific DMABUF formats using a lossy video codec. Opaque, 10-bit, and
	multiplanar formats, among others, are not supported.

*--hwvideo*
	Sets the *--video* option, and also specifies that hardware video encoding and decoding
	should be used if possible. Whether this option improves bandwidth use and latency
	is hardware dependent.


# EXAMPLE 

The following *waypipe ssh* subcommand will attempt to run *weston-flower* on
the server _exserv_, displaying the result on the local system.

```
	waypipe ssh user@exserv weston-flower
```

One can obtain similar behavior by explictly running waypipe and ssh:

```
	waypipe --socket /tmp/socket-client client  &
	ssh -R /tmp/socket-server:/tmp/socket-client user@exserv \\
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

Many applications require specific environment variables to use Wayland instead
of X11. If ssh isn't configured to support loading _~/.ssh/environment_,
one can use _env_ to set the needed variables each time; or run waypipe without
a command, to use the login shell environment.

```
	 waypipe ssh user@host env XDG_SESSION_TYPE=wayland dolphin
```

Waypipe has support for reconnecting a *waypipe client* and a *waypipe server*
instance when whatever was used to transfer data between their sockets fails.
For this to work, waypipe must still be running on both sides of the connection.
As the *waypipe ssh* wrapper will automatically close both the *waypipe client*
and the *waypipe server* when the connection fails, the client and server modes
must be run seprately. For example, to persistently forward applications running
on server _rserv_ to a local Wayland compositor running on _lserv_, one would
first set up a waypipe client instance on _lserv_,

```
	waypipe -s /tmp/waypipe.sock client &
```

and on server _rserv_, establish socket forwarding and run the server

```
	ssh -fN -L /tmp/waypipe-lserv.sock:/tmp/waypipe.sock user@lserv
	waypipe -s /tmp/waypipe-lserv.sock --control /tmp/ctrl-lserv.pipe \\
		--display wayland-lserv server -- sleep inf &
```

then set _WAYLAND_DISPLAY=wayland-lserv_ and run the desired applications.
When the ssh forwarding breaks, on _rserv_, reconnect with

```
	ssh -fN -L /tmp/waypipe-lserv-2.sock:/tmp/waypipe.sock user@lserv
	waypipe recon /tmp/ctrl-lserv.pipe /tmp/waypipe-lserv-2.sock
```

# ENVIRONMENT

When running as a server, by default _WAYLAND_DISPLAY_ will be set for the
invoked process.

If the *--oneshot* flag is set, waypipe will instead set _WAYLAND_SOCKET_ and
inherit an already connected socketpair file descriptor to the invoked (child)
process. Some programs open and close a Wayland connection repeatedly as part
of their initialization, and will not work correctly with this flag.

# EXIT STATUS

*waypipe ssh* will exit with the exit status code from the remote command, or
with return code 1 if there has been an error.

# SEE ALSO

*weston*(1), *ssh*(1)
