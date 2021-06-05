
symgen_path = join_paths(meson.current_source_dir(), 'symgen.py')
sendgen_path = join_paths(meson.current_source_dir(), 'sendgen.py')
fn_list = join_paths(meson.current_source_dir(), 'function_list.txt')

# Include a copy of these protocols in the repository, rather than looking
# for packages containing them, to:
# a) avoid versioning problems as new protocols/methods are introduced
# b) keep the minimum build complexity for waypipe low
# c) be able to relay through newer protocols than are default on a system
protocols = [
	'wayland.xml',
	'xdg-shell.xml',
	'presentation-time.xml',
	'linux-dmabuf-unstable-v1.xml',
	'gtk-primary-selection.xml',
	'input-method-unstable-v2.xml',
	'primary-selection-unstable-v1.xml',
	'virtual-keyboard-unstable-v1.xml',
	'wlr-screencopy-unstable-v1.xml',
	'wlr-export-dmabuf-unstable-v1.xml',
	'wlr-data-control-unstable-v1.xml',
	'wlr-gamma-control-unstable-v1.xml',
	'wayland-drm.xml',
]

protocols_src = []
protocols_src += custom_target(
	'protocol code',
	output: 'protocols.c',
	input: protocols,
	depend_files: [fn_list, symgen_path],
	command: [python3, symgen_path, 'data', fn_list, '@OUTPUT@', '@INPUT@'],
)
protocols_src += custom_target(
	'protocol header',
	output: 'protocols.h',
	input: protocols,
	depend_files: [fn_list, symgen_path],
	command: [python3, symgen_path, 'header', fn_list, '@OUTPUT@', '@INPUT@'],
)

# For use in test
abs_protocols = []
foreach xml : protocols
        abs_protocols += join_paths(meson.current_source_dir(), xml)
endforeach
