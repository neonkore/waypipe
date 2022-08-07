waypipe(1)

# NAME

waypipe - A transparent proxy for Wayland applications

# SYNOPSIS

*waypipe* [options...] *ssh* [ssh options] _destination_ _command..._

*waypipe* [options...] *client*++
*waypipe* [options...] *server* -- _command..._++
*waypipe* *recon* _control_pipe_ _new_socket_path_++
*waypipe* *bench* _bandwidth_++
*waypipe* [*--version*] [*-h*, *--help*]

\[options...\] = [*-c*, *--compress* C] [*-d*, *--debug*] [*-n*, *--no-gpu*] [*-o*, *--oneshot*] [*-s*, *--socket* S] [*--allow-tiled*] [*--control* C] [*--display* D] [*--drm-node* R] [*--remote-node* R] [*--remote-bin* R] [*--login-shell*] [*--threads* T] [*--unlink-socket*] [*--video*[=V]]


# DESCRIPTION

Waypipe is a proxy for Wayland clients, with the aim of supporting behavior
like *ssh -X*.

Prefixing an *ssh ...* command to become *waypipe ssh ...* will automatically
run *waypipe* both locally and remotely, and modify the ssh command to set up
forwarding between the two instances of *waypipe*. The remote instance
will act like a Wayland compositor, letting Wayland applications that are
run remotely be displayed locally.

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

The *waypipe bench* mode can be used to estimate, given a specific
connection _bandwidth_ in MB/sec, which compression options produce the
lowest latency. It tests two synthetic images, one made to be roughly as
compressible as images containing text, and one made to be roughly as
compressible as images containing pictures.

# OPTIONS

*-c C, --compress C*
	Select the compression method applied to data transfers. Options are
	_none_ (for high-bandwidth networks), _lz4_ (intermediate), _zstd_
	(slow connection). The default compression is _none_.† The compression
	level can be chosen by appending = followed by a number. For example,
	if *C* is _zstd=7_, waypipe will use level 7 Zstd compression.

	† In a future version, the default will change to _lz4_.

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
	both the client and the server for their socket paths. The default prefix
	in ssh mode is _/tmp/waypipe_.

*--version*
	Briefly describe Waypipe's version and the features it was built with,
	then quit. Possible features: LZ4 compression support, ZSTD compression
	support, ability to transfer DMABUFs, video compression support, VAAPI
	hardware video de/encoding support.

*--allow-tiled*
	By default, waypipe filters out all advertised DMABUF formats which have
	format layout modifiers, as CPU access to these formats may be very slow.
	Setting this flag disables the filtering. Since tiled images often permit
	faster GPU operations, most OpenGL applications will select tiling modifiers
	when they are available.

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

*--remote-bin R*
	In ssh mode, specify the path *R* to the waypipe binary on the remote
	computer, or its name if it is available in _PATH_. It defaults to
	*waypipe* if this option isn’t passed.

*--login-shell*
	Only for server mode; if no command is being run, open a login shell.

*--threads T*
	Set the number of total threads (including the main thread) which a *waypipe*
	instance will create. These threads will be used to parallelize compression
	operations. This flag is passed on to *waypipe server* when given to *waypipe
	ssh*. The flag also controls the thread count for *waypipe bench*. The default
	behavior (choosable by setting *T* to _0_) is to use half as many threads
	as the computer has hardware threads available.

*--unlink-socket*
	Only for server mode; on shutdown, unlink the Unix socket that waypipe connects to.

*--video[=V]*
	Compress specific DMABUF formats using a lossy video codec. Opaque, 10-bit, and
	multiplanar formats, among others, are not supported. *V* is a comma separated 
	list of options to control the video encoding. Using the *--video* flag without
	setting any options is equivalent to using the default setting of:
	*--video=sw,bpf=120000,h264*. Later options supersede earlier ones.
	
	*sw*
		Use software encoding and decoding.
	
	*hw*
		Use hardware (VAAPI) encoding and decoding, if available. This can be finicky
		and may only work with specific window buffer formats and sizes.
		
	*h264*
		Use H.264 encoded video.
		
	*vp9*
		Use VP9 encoded video.
		
	*bpf=B*
		Set the target bit rate of the video encoder, in units of bits per frame.
		*B* can be written as an integer or with exponential notation; thus
		*--video=bpf=7.5e5* is equivalent to *--video=bpf=750000*.

*--hwvideo*
	Deprecated option, equivalent to --video=hw .

# EXAMPLE 

The following *waypipe ssh* subcommand will attempt to run *weston-flower* on
the server _exserv_, displaying the result on the local system.

```
	waypipe ssh user@exserv weston-flower
```

One can obtain similar behavior by explicitly running waypipe and ssh:

```
	waypipe --socket /tmp/socket-client client  &
	ssh -R /tmp/socket-server:/tmp/socket-client user@exserv \\
		waypipe --socket /tmp/socket-server server -- weston-flower
	kill %1
```

Waypipe may be run locally without an SSH connection by specifying matching
socket paths. For example:

```
	waypipe --socket /tmp/waypipe.sock client &
	waypipe --socket /tmp/waypipe.sock server weston-simple-dmabuf-egl
	kill %1
	rm /tmp/waypipe.sock
```

Using transports other than SSH is a bit more complicated. A recipe with ncat
to connect to _remote_ from computer _local_:

```
    $ waypipe --socket /tmp/waypipe-remote.sock client &
    $ ncat --ssl -lk 12345 --sh-exec 'ncat -U /tmp/waypipe-remote.sock' &
    $ ssh user@remote

    > ncat -lkU /tmp/waypipe-local.sock --sh-exec 'ncat --ssl local 12345' &
    > waypipe --display wayland-local \\
                --socket /tmp/waypipe-local.sock server -- sleep inf &
    > WAYLAND_DISPLAY=wayland-local application
```

Given a certificate file, socat can also provide an encrypted connection
(remove 'verify=0' to check certificates):

```
    $ waypipe --socket /tmp/waypipe-remote.sock client &
    $ socat openssl-listen:12345,reuseaddr,cert=certificate.pem,verify=0,fork \\
        unix-connect:/tmp/waypipe-remote.sock
    $ ssh user@remote

    > socat unix-listen:/tmp/waypipe-local.sock,reuseaddr,fork \\
        openssl-connect:local:12345,verify=0 &
    > waypipe --socket /tmp/waypipe-local.sock server -- application
```

Many applications require specific environment variables to use Wayland instead
of X11. If ssh isn't configured to support loading _~/.ssh/environment_, or
to allow specific variables to be set with _AcceptEnv_/_SetEnv_, one can run
*waypipe ssh* without a command (and thereby open a login shell), or use *env*
to set the needed variables each time:

```
	 waypipe ssh user@host env XDG_SESSION_TYPE=wayland dolphin
```

In some cases, one may wish to set environment variables for the *waypipe
server* process itself; the above trick with *env* will not do this, because the
*env* process will be a child of *waypipe server*, not the other way around.
Instead, one can use _~/.ssh/environment_, or use the *--remote-bin* option to
change the remote Waypipe instance to a shell script that sets the environment
before running the actual *waypipe* program.

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

# BUGS

File bug reports at: https://gitlab.freedesktop.org/mstoeckl/waypipe/

Some programs (gnome-terminal, firefox, kate, among others) have special
mechanisms to ensure that only one process is running at a time. Starting
those programs under Waypipe while they are running under a different
Wayland compositor may silently open a window or tab in the original
instance of the program. Such programs may have a command line argument
to create a new instance.

# SEE ALSO

*weston*(1), *ssh*(1), *socat(1)*, *ncat(1)*
