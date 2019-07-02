project(
	'waypipe',
	'c',
	license: 'MIT/Expat',
	meson_version: '>=0.47.0',
	default_options: [
		'c_std=c11',
		'warning_level=3',
		'werror=true',
	],
	version: '0.2.0',
)

cc = meson.get_compiler('c')

# mention version
version = '"@0@"'.format(meson.project_version())
add_project_arguments('-DWAYPIPE_VERSION=@0@'.format(version), language: 'c')

python3 = import('python').find_installation()
# Make build reproducible if possible
if cc.has_argument('-fmacro-prefix-map=/prefix/to/hide=')
	prefix_finder = 'import os.path; print(os.path.join(os.path.relpath(\'@0@\', \'@1@\'),\'\'))'
	r = run_command(python3, '-c', prefix_finder.format(meson.source_root(), meson.build_root()))
	relative_dir = r.stdout().strip()
	add_project_arguments(
		'-fmacro-prefix-map=@0@='.format(relative_dir),
		language: 'c',
	)
else
	length_finder = 'import os.path; print(len(os.path.join(os.path.relpath(\'@0@\', \'@1@\'),\'\')))'
	rel_src_dir_length = run_command(python3, '-c',
	length_finder.format(meson.source_root(), meson.build_root())).stdout().strip()

	add_project_arguments(
		'-DWAYPIPE_SRC_DIR_LENGTH=@0@'.format(rel_src_dir_length),
		language: 'c',
	)
endif

wayland_client = dependency('wayland-client', version: '>=1.15') # scanner headers
wayland_server = dependency('wayland-server', version: '>=1.15') # scanner headers
wayland_scanner = dependency('wayland-scanner', native: true, version: '>=1.15') # public-code
wayland_protos = dependency('wayland-protocols', version: '>=1.12') # xdg-shell
libgbm = dependency('gbm', required: get_option('with_dmabuf'))
libdrm = dependency('libdrm', required: get_option('with_dmabuf'))
if libgbm.found() and libdrm.found()
	add_project_arguments('-DHAS_DMABUF=1', language: 'c')
endif
libffi = dependency('libffi')
pthreads = dependency('threads')
rt = cc.find_library('rt')
# XXX dtrace -G (Solaris, FreeBSD, NetBSD) isn't supported yet
is_linux = host_machine.system() == 'linux'
is_darwin = host_machine.system() == 'darwin'
if (is_linux or is_darwin) and cc.has_header('sys/sdt.h')
	add_project_arguments('-DHAS_USDT=1', language: 'c')
endif
liblz4 = dependency('liblz4', required: get_option('with_lz4'))
if liblz4.found()
	add_project_arguments('-DHAS_LZ4=1', language: 'c')
endif
libzstd = dependency('libzstd', version: '>=1.4.0', required: get_option('with_zstd'))
if libzstd.found()
	add_project_arguments('-DHAS_ZSTD=1', language: 'c')
endif
libavcodec = dependency('libavcodec', required: get_option('with_video'))
libavutil = dependency('libavutil', required: get_option('with_video'))
libswscale = dependency('libswscale', required: get_option('with_video'))
if libavcodec.found() and libavutil.found() and libswscale.found()
	add_project_arguments('-DHAS_VIDEO=1', language: 'c')
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
	wayland_client.partial_dependency(compile_args: true), # protocol headers need these
]

waypipe_includes = []
if libdrm.found()
	waypipe_includes += include_directories(libdrm.get_pkgconfig_variable('includedir'))
endif

lib_waypipe_src = static_library(
	'waypipe_src',
	waypipe_source_files,
	include_directories: waypipe_includes,
	dependencies: waypipe_dependencies,
)

waypipe_prog = executable(
	'waypipe',
	['waypipe.c'],
	link_with: lib_waypipe_src,
	install: true
)

scdoc = dependency('scdoc', version: '>=1.9.4', native: true, required: get_option('man-pages'))
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
	['test/diff_roundtrip.c'],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src,
)
test('Whether diff operations successfully roundtrip', test_diff)
test_damage = executable(
	'damage_merge',
	['test/damage_merge.c'],
	link_with: lib_waypipe_src
)
test('If damage rectangles merge efficiently', test_damage)
test_mirror = executable(
	'fd_mirror',
	['test/fd_mirror.c'],
	link_with: lib_waypipe_src,
	dependencies: [libgbm]
)
# disable leak checking, because library code is often responsible
test('How well file descriptors are replicated', test_mirror, env: ['ASAN_OPTIONS=detect_leaks=0'])
test_parse = executable(
	'wire_parse',
	['test/wire_parse.c'],
	link_with: lib_waypipe_src,
	dependencies: [libffi, wayland_client.partial_dependency(compile_args: true)]
)
test('That protocol parsing fails cleanly', test_parse)
weston_prog = find_program('weston', required: false)
weston_shm_prog = find_program('weston-simple-shm', required: false)
weston_egl_prog = find_program('weston-simple-egl', required: false)
weston_dma_prog = find_program('weston-simple-dmabuf-drm', required: false)
envlist = [
	'TEST_WAYPIPE_PATH=@0@'.format(waypipe_prog.full_path()),
]
if weston_prog.found() and weston_shm_prog.found() and weston_egl_prog.found()
	modenv = envlist
	modenv += 'TEST_WESTON_PATH=@0@'.format(weston_prog.path())
	modenv += 'TEST_WESTON_SHM_PATH=@0@'.format(weston_shm_prog.path())
	modenv += 'TEST_WESTON_EGL_PATH=@0@'.format(weston_egl_prog.path())
	modenv += 'TEST_WESTON_DMA_PATH=@0@'.format(weston_dma_prog.path())
	test_headless = join_paths(meson.current_source_dir(), 'test/headless.py')
	test('If clients crash when run with weston via waypipe', python3, args: test_headless, env: modenv)
endif

test_startup = join_paths(meson.current_source_dir(), 'test/startup_failure.py')
test('That waypipe exits cleanly given a bad setup', python3, args: test_startup, env: envlist)
