project(
	'waypipe',
	'c',
	license: 'MIT/Expat',
	meson_version: '>=0.48.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
	version: '0.0.0',
)

cc = meson.get_compiler('c')

# mention version
version = '"@0@"'.format(meson.project_version())
add_project_arguments('-DWAYPIPE_VERSION=@0@'.format(version), language: 'c')

# Make build reproducible if possible
if cc.get_id() == 'gcc'
	r = run_command('python3', '-c', 'import os.path; print(os.path.join(os.path.relpath(\'@0@\', \'@1@\'),\'\'))'.format(meson.source_root(), meson.build_root()))
		relative_dir = r.stdout().strip()
	add_project_arguments(
		'-fmacro-prefix-map=@0@='.format(relative_dir),
		language: 'c',
	)
else
	length_finder = 'import os.path; print(len(os.path.join(os.path.relpath(\'@0@\', \'@1@\'),\'\')))'
	rel_src_dir_length = run_command('python3', '-c',
	length_finder.format(meson.source_root(), meson.build_root())).stdout().strip()

	add_project_arguments(
		'-DWAYPIPE_SRC_DIR_LENGTH=@0@'.format(rel_src_dir_length),
		language: 'c',
	)
endif

wayland_client = dependency('wayland-client', version: '>=1.17')
wayland_protos = dependency('wayland-protocols', version: '>=1.17')
wayland_server = dependency('wayland-server', version: '>=1.17')
libffi         = dependency('libffi')
rt             = cc.find_library('rt')

subdir('protocols')

executable(
	'waypipe',
	['waypipe.c', 'client.c', 'handlers.c', 'parsing.c', 'server.c', 'util.c'],
	dependencies : [
		libffi,          # To call wayland protocol functions
		protos,          # Wayland protocol data
		rt,              # For shared memory
		wayland_client   # For wl_display_connnect
	],
	install: true
)

scdoc = dependency('scdoc', version: '>=1.9.4', native: true)
scdoc_prog = find_program(scdoc.get_pkgconfig_variable('scdoc'), native: true)
sh = find_program('sh', native: true)
mandir = get_option('mandir')
custom_target(
	'waypipe.1',
	input: 'waypipe.scd',
	output: 'waypipe.1',
	command: [
		sh, '-c', '@0@ < @INPUT@ > @1@'.format(scdoc_prog.path(), 'waypipe.1')
	],
	install: true,
	install_dir: '@0@/man1'.format(mandir)
)

