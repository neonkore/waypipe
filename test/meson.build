
common_src = static_library(
	'common',
	'common.c',
	include_directories: waypipe_includes
)
# Testing
test_diff = executable(
	'diff_roundtrip',
	['diff_roundtrip.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src]
)
test('Whether diff operations successfully roundtrip', test_diff, timeout: 60)
test_damage = executable(
	'damage_merge',
	['damage_merge.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src]
)
test('If damage rectangles merge efficiently', test_damage, timeout: 5)
test_mirror = executable(
	'fd_mirror',
	['fd_mirror.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src],
	dependencies: [libgbm]
)
# disable leak checking, because library code is often responsible
test('How well buffers are replicated', test_mirror, env: ['ASAN_OPTIONS=detect_leaks=0'], timeout: 40)
test_proto_functions = files('protocol_functions.txt')
proto_send_src = custom_target(
	'protocol_control message serialization',
	output: 'protocol_functions.h',
	depend_files: [test_proto_functions, sendgen_path] + abs_protocols,
	command: [python3, sendgen_path, test_proto_functions, '@OUTPUT@'] + abs_protocols,
)
test_protocol = executable(
	'protocol_control',
	['protocol_control.c', proto_send_src],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src]
)
test('That common Wayland message patterns work', test_protocol, env: ['ASAN_OPTIONS=detect_leaks=0'], timeout: 20)
test_pipe = executable(
	'pipe_mirror',
	['pipe_mirror.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src]
)
test('How well pipes are replicated', test_pipe, timeout: 20)
test_fnlist = files('test_fnlist.txt')
testproto_src = custom_target(
	'test-proto code',
	output: 'protocol-@BASENAME@.c',
	input: 'test-proto.xml',
	depend_files: [test_fnlist, symgen_path],
	command: [python3, symgen_path, 'data', test_fnlist,  '@OUTPUT@', '@INPUT@'],
)
testproto_header = custom_target(
	'test-proto client-header',
	output: 'protocol-@BASENAME@.h',
	input: 'test-proto.xml',
	depend_files: [test_fnlist, symgen_path],
	command: [python3, symgen_path, 'header', test_fnlist,  '@OUTPUT@', '@INPUT@'],
)
test_parse = executable(
	'wire_parse',
	['wire_parse.c', testproto_src, testproto_header],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src],
)
test('That protocol parsing fails cleanly', test_parse, timeout: 5)

fake_ssh = executable(
	'ssh',
	['fake_ssh.c']
)

weston_dep = dependency('weston', required: false)
testprog_paths = []
if weston_dep.found()
	# Sometimes weston's test clients are installed here instead
	testprog_paths += weston_dep.get_pkgconfig_variable('libexecdir')
endif
weston_prog = find_program('weston', required: false)
base_envlist = [
	'TEST_WAYPIPE_PATH=@0@'.format(waypipe_prog.full_path()),
]

headless_envlist = base_envlist
if weston_prog.found()
	headless_envlist += 'TEST_WESTON_PATH=@0@'.format(weston_prog.path())
endif
test_programs = [
	['TEST_WESTON_SHM_PATH', 'weston-simple-shm'],
	# ['TEST_WESTON_EGL_PATH', 'weston-simple-egl'],
	['TEST_WESTON_TERM_PATH', 'weston-terminal'],
	['TEST_WESTON_PRES_PATH', 'weston-presentation-shm'],
	['TEST_WESTON_SUBSURF_PATH', 'weston-subsurfaces'],
]
if has_dmabuf
	test_programs += [['TEST_WESTON_DMA_PATH', 'weston-simple-dmabuf-egl']]
endif
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
		headless_envlist += '@0@=@1@'.format(t[0], test_prog.path())
	endif
endforeach

if weston_prog.found() and have_test_progs
	test_headless = join_paths(meson.current_source_dir(), 'headless.py')
	test('If clients crash when run with weston via waypipe', python3, args: test_headless, env: headless_envlist, timeout: 30)
endif

sleep_prog = find_program('sleep')
startup_envlist = base_envlist
startup_envlist += ['TEST_SLEEP_PATH=' + sleep_prog.path()]
startup_envlist += ['TEST_FAKE_SSH_PATH=' + fake_ssh.full_path()]
test_startup = join_paths(meson.current_source_dir(), 'startup_failure.py')
test('That waypipe exits cleanly given a bad setup',
        python3, args: test_startup, env: startup_envlist, timeout: 30
)

fuzz_hook_ext = executable(
	'fuzz_hook_ext',
	['fuzz_hook_ext.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src],
	dependencies: [pthreads]
)
fuzz_hook_int = executable(
	'fuzz_hook_int',
	['fuzz_hook_int.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src],
	dependencies: [pthreads]
)
fuzz_hook_det = executable(
	'fuzz_hook_det',
	['fuzz_hook_det.c'],
	include_directories: waypipe_includes,
	link_with: [lib_waypipe_src, common_src]
)
test('That `waypipe bench` doesn\'t crash',
	waypipe_prog, timeout: 20,
	args:  ['--threads', '2', '--test-size', '16384', 'bench', '100.0']
)
