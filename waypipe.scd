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

*-o, --oneshot*
	Only permit a single connection, and exit when it is closed.

*-s S, --socket S*
	Use *S* as the path for the unix socket.

*-v, --version*
	Show the version number and quit.

# EXAMPLE 

The following *waypipe ssh* subcommand will attempt to run *weston-flower* on
the server _exserv_, displaying the result on the local system.

```
	waypipe -o ssh user@exserv weston-flower
```

One can obtain similar behavior by explictly running waypipe and ssh:

```
	waypipe -o --socket /tmp/socket-client client  &
	ssh -R/tmp/socket-server:/tmp/socket-client -t user@exserv waypipe -o --socket /tmp/socket-server server -- weston-flower
	kill %1
```

	
# ENVIRONMENT

When running as a server, by default _WAYLAND_DISPLAY_ will be set for the
invoked process. If the *--oneshot* flag is set, waypipe will instead set
_WAYLAND_SOCKET_ and inherit a corresponding file descriptor to the invoked
(child) process.

# SEE ALSO

*weston*(1)
