
# Testing
test_diff = executable(
	'diff_roundtrip',
	['diff_roundtrip.c'],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src
)
test('Whether diff operations successfully roundtrip', test_diff, timeout: 60)
test_damage = executable(
	'damage_merge',
	['damage_merge.c'],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src
)
test('If damage rectangles merge efficiently', test_damage, timeout: 5)
test_mirror = executable(
	'fd_mirror',
	['fd_mirror.c'],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src,
	dependencies: [libgbm]
)
# disable leak checking, because library code is often responsible
test('How well file descriptors are replicated', test_mirror, env: ['ASAN_OPTIONS=detect_leaks=0'], timeout: 40)
test_fnlist = files('test_fnlist.txt')
testproto_src = custom_target(
	'test-proto code',
	output: '@BASENAME@-data.c',
	input: 'test-proto.xml',
	command: [python3, symgen_path, 'data', test_fnlist, '@INPUT@', '@OUTPUT@'],
)
testproto_header = custom_target(
	'test-proto client-header',
	output: '@BASENAME@-defs.h',
	input: 'test-proto.xml',
	command: [python3, symgen_path, 'header', test_fnlist, '@INPUT@', '@OUTPUT@'],
)
test_parse = executable(
	'wire_parse',
	['wire_parse.c', testproto_src, testproto_header],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src,
	dependencies: [protos]
)
test('That protocol parsing fails cleanly', test_parse, timeout: 5)

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
	# ['TEST_WESTON_EGL_PATH', 'weston-simple-egl'],
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
	test_headless = join_paths(meson.current_source_dir(), 'headless.py')
	test('If clients crash when run with weston via waypipe', python3, args: test_headless, env: envlist, timeout: 10)
endif
test_startup = join_paths(meson.current_source_dir(), 'startup_failure.py')
test('That waypipe exits cleanly given a bad setup', python3, args: test_startup, env: envlist, timeout: 10)
fuzz_hook_ext = executable(
	'fuzz_hook_ext',
	['fuzz_hook_ext.c'],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src,
	dependencies: [pthreads]
)
fuzz_hook_int = executable(
	'fuzz_hook_int',
	['fuzz_hook_int.c'],
	include_directories: waypipe_includes,
	link_with: lib_waypipe_src,
	dependencies: [pthreads]
)
