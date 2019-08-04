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
	version: '0.4.0',
)

cc = meson.get_compiler('c')
config_data = configuration_data()

# mention version
version = '"@0@"'.format(meson.project_version())
config_data.set('WAYPIPE_VERSION', version)

# Make build reproducible if possible
python3 = import('python').find_installation()
prefix_finder = 'import os.path; print(os.path.join(os.path.relpath(\'@0@\', \'@1@\'),\'\'))'
r = run_command(python3, '-c', prefix_finder.format(meson.source_root(), meson.build_root()))
relative_dir = r.stdout().strip()
if cc.has_argument('-fmacro-prefix-map=/prefix/to/hide=')
	add_project_arguments(
		'-fmacro-prefix-map=@0@='.format(relative_dir),
		language: 'c',
	)
else
	add_project_arguments(
		'-DWAYPIPE_REL_SRC_DIR="@0@"'.format(relative_dir),
		language: 'c',
	)
endif

libgbm = dependency('gbm', required: get_option('with_dmabuf'))
libdrm = dependency('libdrm', required: get_option('with_dmabuf'))
if libgbm.found() and libdrm.found()
	config_data.set('HAS_DMABUF', 1, description: 'Support DMABUF replication')
endif
pthreads = dependency('threads')
rt = cc.find_library('rt')
# XXX dtrace -G (Solaris, FreeBSD, NetBSD) isn't supported yet
is_linux = host_machine.system() == 'linux'
is_darwin = host_machine.system() == 'darwin'
if (is_linux or is_darwin) and cc.has_header('sys/sdt.h')
	config_data.set('HAS_USDT', 1, description: 'Enable static trace probes')
endif
liblz4 = dependency('liblz4', version: '>=1.7.0', required: get_option('with_lz4'))
if liblz4.found()
	config_data.set('HAS_LZ4', 1, description: 'Enable LZ4 compression')
endif
libzstd = dependency('libzstd', version: '>=0.4.6', required: get_option('with_zstd'))
if libzstd.found()
	config_data.set('HAS_ZSTD', 1, description: 'Enable Zstd compression')
endif
libavcodec = dependency('libavcodec', required: get_option('with_video'))
libavutil = dependency('libavutil', required: get_option('with_video'))
libswscale = dependency('libswscale', required: get_option('with_video'))
if libavcodec.found() and libavutil.found() and libswscale.found()
	config_data.set('HAS_VIDEO', 1, description: 'Enable video (de)compression')
endif
libva = dependency('libva', required: get_option('with_vaapi'))
if libva.found()
	config_data.set('HAS_VAAPI', 1, description: 'Enable hardware video (de)compression with VAAPI')
endif

subdir('protocols')

waypipe_source_files = ['client.c', 'dmabuf.c', 'handlers.c', 'kernel.c', 'mainloop.c', 'parsing.c', 'server.c', 'shadow.c', 'interval.c', 'util.c', 'video.c']
waypipe_dependencies = [
	libgbm,          # General GPU buffer creation, aligned with dmabuf proto
	liblz4,          # Fast compression option
	libzstd,         # Slow compression option
	libavcodec,libavutil,libswscale, # Video encoding
	pthreads,        # To run expensive computations in parallel
	protos,          # Wayland protocol data
	rt,              # For shared memory
	libva,           # For NV12->RGB conversions
]

waypipe_includes = []
if libdrm.found()
	waypipe_includes += include_directories(libdrm.get_pkgconfig_variable('includedir'))
endif

# Conditionally compile SIMD-optimized code.
# (The meson simd module is a bit too limited for this)
kernel_libs = []
if cc.has_argument('-mavx512f') and cc.has_argument('-mlzcnt') and cc.has_argument('-mbmi')
	kernel_libs += static_library('kernel_avx512f', 'kernel_avx512f.c', c_args:['-mavx512f', '-mlzcnt', '-mbmi'])
	config_data.set('HAVE_AVX512F', 1, description: 'Compiler supports AVX-512F')
endif
if cc.has_argument('-mavx2') and cc.has_argument('-mlzcnt') and cc.has_argument('-mbmi')
	kernel_libs += static_library('kernel_avx2', 'kernel_avx2.c', c_args:['-mavx2', '-mlzcnt', '-mbmi'])
	config_data.set('HAVE_AVX2', 1, description: 'Compiler supports AVX2')
endif
if cc.has_argument('-msse4.1')
	kernel_libs += static_library('kernel_sse41', 'kernel_sse41.c', c_args:['-msse4.1'])
	config_data.set('HAVE_SSE41', 1, description: 'Compiler supports SSE 4.1')
endif
if host_machine.cpu_family() == 'aarch64' or cc.has_argument('-mfpu=neon')
	neon_args = host_machine.cpu_family() == 'aarch64' ? [] : ['-mfpu=neon']

	# Clang additionally enforces that NEON code only be compiled
	# to target a CPU that actually supports NEON instructions,
	# so bump the host CPU version for the optionally executed code only.
	if host_machine.cpu_family() == 'arm' and cc.get_id() == 'clang'
		host_cpu = host_machine.cpu()
		if host_cpu.contains('4') or host_cpu.contains('5') or host_cpu.contains('6')
			neon_args += ['-march=armv7-a']
		endif
	endif

	kernel_libs += static_library('kernel_neon', 'kernel_neon.c', c_args:neon_args)
	config_data.set('HAVE_NEON', 1, description: 'Compiler supports NEON')
endif

configure_file(
	output: 'config-waypipe.h',
	configuration: config_data,
)

lib_waypipe_src = static_library(
	'waypipe_src',
	waypipe_source_files,
	include_directories: waypipe_includes,
	link_with: kernel_libs,
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
gen_path = join_paths(meson.current_source_dir(), 'protocols/symgen.py')
test_fnlist = files('test/test_fnlist.txt')
testproto_src = custom_target(
	'test-proto code',
	output: '@BASENAME@-data.c',
	input: 'test/test-proto.xml',
	command: [python3, gen_path, 'data', test_fnlist, '@INPUT@', '@OUTPUT@'],
)
testproto_header = custom_target(
	'test-proto client-header',
	output: '@BASENAME@-defs.h',
	input: 'test/test-proto.xml',
	command: [python3, gen_path, 'header', test_fnlist, '@INPUT@', '@OUTPUT@'],
)
test_parse = executable(
	'wire_parse',
	['test/wire_parse.c', testproto_src, testproto_header],
	link_with: lib_waypipe_src,
	dependencies: [protos]
)
test('That protocol parsing fails cleanly', test_parse)

weston_dep = dependency('weston', required: false)
testprog_paths = []
if weston_dep.found()
	# Sometimes weston's test clients are installed here instead
	testprog_paths += weston_dep.get_pkgconfig_variable('libexecdir')
endif
weston_prog = find_program('weston', required: false)
envlist = [
	'TEST_WAYPIPE_PATH=@0@'.format(waypipe_prog.full_path()),
]
if weston_prog.found()
	envlist += 'TEST_WESTON_PATH=@0@'.format(weston_prog.path())
endif
test_programs = [
	['TEST_WESTON_SHM_PATH', 'weston-simple-shm'],
	['TEST_WESTON_EGL_PATH', 'weston-simple-egl'],
	['TEST_WESTON_DMA_PATH', 'weston-simple-dmabuf-drm'],
	['TEST_WESTON_TERM_PATH', 'weston-terminal'],
	['TEST_WESTON_PRES_PATH', 'weston-presentation-shm'],
	['TEST_WESTON_SUBSURF_PATH', 'weston-subsurfaces'],
]
have_test_progs = false
foreach t : test_programs
	test_prog = find_program(t[1], required: false)
	foreach p : testprog_paths
		if not test_prog.found()
			test_prog = find_program(join_paths(p, t[1]), required: false)
		endif
	endforeach
	if test_prog.found()
		have_test_progs = true
		envlist += '@0@=@1@'.format(t[0], test_prog.path())
	endif
endforeach

if weston_prog.found() and have_test_progs
	test_headless = join_paths(meson.current_source_dir(), 'test/headless.py')
	test('If clients crash when run with weston via waypipe', python3, args: test_headless, env: envlist)
endif
test_startup = join_paths(meson.current_source_dir(), 'test/startup_failure.py')
test('That waypipe exits cleanly given a bad setup', python3, args: test_startup, env: envlist)
fuzz_hook = executable(
	'fuzz_hook',
	['test/fuzz_hook.c'],
	link_with: lib_waypipe_src,
	dependencies: [pthreads]
)
