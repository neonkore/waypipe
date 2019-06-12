wl_protocol_dir = wayland_protos.get_pkgconfig_variable('pkgdatadir')
wayland_dir = wayland_client.get_pkgconfig_variable('pkgdatadir')

wayland_scanner_prog = find_program(wayland_scanner.get_pkgconfig_variable('wayland_scanner'))

# The last argument in each list should be the protocol name; appending
# .xml , and path-concatenating the preceding elements, should produce a path
# to a protocol xml file.
protocols = [
	[wayland_dir, 'wayland'],
	[wl_protocol_dir, 'stable/xdg-shell/', 'xdg-shell'],
	[wl_protocol_dir, 'stable/presentation-time/', 'presentation-time'],
	[wl_protocol_dir, 'unstable/linux-dmabuf/', 'linux-dmabuf-unstable-v1'],
	['gtk-primary-selection'],
	['input-method-unstable-v2'],
	['virtual-keyboard-unstable-v1'],
	['wlr-screencopy-unstable-v1'],
#	['wlr-export-dmabuf-unstable-v1'],
	['wayland-drm'],
]

protocols_src = []
protocols_headers = []
foreach path_parts : protocols
	xml = join_paths(path_parts) + '.xml'
	base_name = path_parts[-1]

	protocols_src += custom_target(
		'@0@ code'.format(base_name),
		output : '@0@-data.c'.format(base_name),
		input : xml,
		command : [wayland_scanner_prog, 'public-code', '@INPUT@', '@OUTPUT@'],
	)
	protocols_headers += custom_target(
		'@0@ client-header'.format(base_name),
		output : '@0@-client-defs.h'.format(base_name),
		input : xml,
		command : [wayland_scanner_prog, 'client-header', '@INPUT@', '@OUTPUT@'],
	)
	protocols_headers += custom_target(
		'@0@ server-header'.format(base_name),
		output : '@0@-server-defs.h'.format(base_name),
		input : xml,
		command : [wayland_scanner_prog, 'server-header', '@INPUT@', '@OUTPUT@'],
	)
endforeach

# the src files do not require the headers
lib_protocols = static_library(
	'protocols',
	protocols_src,
	dependencies: [wayland_client] # for the header files, only
)
protos = declare_dependency(
	link_with: lib_protocols,
	sources: protocols_headers,
)
