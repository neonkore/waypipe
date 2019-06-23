wl_protocol_dir = wayland_protos.get_pkgconfig_variable('pkgdatadir')
wayland_dir = wayland_client.get_pkgconfig_variable('pkgdatadir')

wayland_scanner_prog = find_program(wayland_scanner.get_pkgconfig_variable('wayland_scanner'))

protocols = [
	wayland_dir + '/wayland.xml',
	wl_protocol_dir + '/stable/xdg-shell/xdg-shell.xml',
	wl_protocol_dir + '/stable/presentation-time/presentation-time.xml',
	wl_protocol_dir + '/unstable/linux-dmabuf/linux-dmabuf-unstable-v1.xml',
	'gtk-primary-selection.xml',
	'input-method-unstable-v2.xml',
	'virtual-keyboard-unstable-v1.xml',
	'wlr-screencopy-unstable-v1.xml',
	'wlr-export-dmabuf-unstable-v1.xml',
	'wayland-drm.xml',
]

protocols_src = []
protocols_headers = []
foreach xml : protocols
	protocols_src += custom_target(
		'@0@ code'.format(xml.underscorify()),
		output: '@BASENAME@-data.c',
		input: xml,
		command: [wayland_scanner_prog, 'public-code', '@INPUT@', '@OUTPUT@'],
	)
	protocols_headers += custom_target(
		'@0@ client-header'.format(xml.underscorify()),
		output: '@BASENAME@-client-defs.h',
		input: xml,
		command: [wayland_scanner_prog, 'client-header', '@INPUT@', '@OUTPUT@'],
	)
	protocols_headers += custom_target(
		'@0@ server-header'.format(xml.underscorify()),
		output: '@BASENAME@-server-defs.h',
		input: xml,
		command: [wayland_scanner_prog, 'server-header', '@INPUT@', '@OUTPUT@'],
	)
endforeach

# the src files do not require the headers
lib_protocols = static_library(
	'protocols',
	protocols_src,
	dependencies: wayland_client.partial_dependency(compile_args: true),
)
protos = declare_dependency(
	link_with: lib_protocols,
	sources: protocols_headers,
)
