project(
	'waypipe',
	'c',
	license: 'MIT/Expat',
	meson_version: '>=0.47.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
	version: '0.1.0',
)

cc = meson.get_compiler('c')

# mention version
version = '"@0@"'.format(meson.project_version())
add_project_arguments('-DWAYPIPE_VERSION=@0@'.format(version), language: 'c')

# Make build reproducible if possible
if cc.has_argument('-fmacro-prefix-map=/prefix/to/hide=')
	prefix_finder = 'import os.path; print(os.path.join(os.path.relpath(\'@0@\', \'@1@\'),\'\'))'
	r = run_command('python3', '-c', prefix_finder.format(meson.source_root(), meson.build_root()))
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

wayland_client = dependency('wayland-client', version: '>=1.15') # WAYLAND_DISPLAY=path
wayland_server = dependency('wayland-server', version: '>=1.15') # WAYLAND_DISPLAY=path
wayland_protos = dependency('wayland-protocols', version: '>=1.12') # xdg-shell
wayland_scanner = dependency('wayland-scanner', native: true, version: '>=1.15') # public-code
libgbm = dependency('gbm', required : get_option('with_dmabuf'))
libdrm = dependency('libdrm', required : get_option('with_dmabuf'))
if libgbm.found() and libdrm.found()
	add_project_arguments('-DHAS_DMABUF=1', language : 'c')
endif
libffi = dependency('libffi')
pthreads = dependency('threads')
rt = cc.find_library('rt')
if cc.has_header('sys/sdt.h')
	add_project_arguments('-DHAS_USDT=1', language : 'c')
endif
liblz4 = dependency('liblz4')
libzstd = dependency('libzstd')
libavcodec = dependency('libavcodec', required : get_option('with_video'))
libavutil = dependency('libavutil', required : get_option('with_video'))
libswscale = dependency('libswscale', required : get_option('with_video'))
if libavcodec.found() and libavutil.found() and libswscale.found()
	add_project_arguments('-DHAS_VIDEO=1', language : 'c')
endif

subdir('protocols')

waypipe_source_files = ['client.c', 'dmabuf.c', 'handlers.c', 'mainloop.c', 'parsing.c', 'server.c', 'shadow.c', 'interval.c', 'util.c', 'video.c']
waypipe_dependencies = [
	libgbm,          # General GPU buffer creation, aligned with dmabuf proto
	libffi,          # To call wayland protocol functions
	liblz4,          # Fast compression option
	libzstd,         # Slow compression option
	libavcodec,libavutil,libswscale, # Video encoding
	pthreads,        # To run expensive computations in parallel
	protos,          # Wayland protocol data
	rt,              # For shared memory
	wayland_client   # For wl_display_connnect
]

waypipe_includes = []
if libdrm.found()
	waypipe_includes += libdrm.get_pkgconfig_variable('includedir')
endif

executable(
	'waypipe',
	['waypipe.c'] + waypipe_source_files,
	dependencies : waypipe_dependencies,
	include_directories : waypipe_includes,
	install: true
)

message(waypipe_includes)

scdoc = dependency('scdoc', version: '>=1.9.4', native: true, required: false)
if scdoc.found()
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
endif

# Testing
test_diff = executable(
	'diff_roundtrip',
	['test/diff_roundtrip.c'] + ['shadow.c', 'util.c', 'dmabuf.c', 'interval.c', 'video.c'],
	include_directories : waypipe_includes,
	dependencies: waypipe_dependencies
)
test('Whether diff operations successfully roundtrip', test_diff)
test_damage = executable('damage_merge', ['test/damage_merge.c'] + ['interval.c', 'util.c'])
test('If damage rectangles merge efficiently', test_damage)

