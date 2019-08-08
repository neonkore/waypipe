
# todo: make function list dependency explicit

symgen_path = join_paths(meson.current_source_dir(), 'symgen.py')
fn_list = join_paths(meson.current_source_dir(), 'function_list.txt')

wayland_protos = dependency('wayland-protocols', version: '>=1.12') # xdg-shell
wayland_dep = dependency('wayland-client', required: false)
if not wayland_dep.found()
	wayland_dep = dependency('wayland-server', required: true)
endif
wayland_dir = wayland_dep.get_pkgconfig_variable('pkgdatadir')
wl_protocol_dir = wayland_protos.get_pkgconfig_variable('pkgdatadir')

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
	'wlr-data-control-unstable-v1.xml',
	'wayland-drm.xml',
]

protocols_src = []
protocols_headers = []
protocols_headers += configure_file(input: 'symgen_types.h', copy: true, output: 'symgen_types.h')
foreach xml : protocols
	protocols_src += custom_target(
		'@0@ code'.format(xml.underscorify()),
		output: '@BASENAME@-data.c',
		input: xml,
		command: [python3, symgen_path, 'data', fn_list, '@INPUT@', '@OUTPUT@'],
	)
	protocols_headers += custom_target(
		'@0@ client-header'.format(xml.underscorify()),
		output: '@BASENAME@-defs.h',
		input: xml,
		command: [python3, symgen_path, 'header', fn_list, '@INPUT@', '@OUTPUT@'],
	)
endforeach

# the src files do not require the headers
lib_protocols = static_library(
	'protocols',
	protocols_src,
)
protos = declare_dependency(
	link_with: lib_protocols,
	sources: protocols_headers,
)
