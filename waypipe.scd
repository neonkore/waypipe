waypipe(1)

# NAME

waypipe - A transparent proxy for Wayland applications

# SYNOPSIS

*waypipe* [options...] client socket_path++
*waypipe* [options...] server socket_path -- command

# OPTIONS

*-h, --help*
	Show help message and quit.

*-v, --version*
	Show the version number and quit.

# DESCRIPTION

waypipe is a proxy for Wayland clients, with the aim of supporting
behavior like *ssh -X*.

# EXAMPLE 

```
	waypipe client /tmp/socket-client &
	ssh -R/tmp/socket-server:/tmp/socket-client localhost waypipe server /tmp/socket-server -- weston-flower
	kill %1
```
	
# ENVIRONMENT

In server mode, the environment variable _WAYLAND_SOCKET_ is set, and the matching
socket is inherited unto children.

# SEE ALSO

*weston*(1)
