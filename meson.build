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
	version: '0.7.0',
)

# DEFAULT_SOURCE implies POSIX_C_SOURCE 200809L + extras like CMSG_LEN
# requires glibc >= 4.19 (2014), freebsd libc (since 2016?), musl >= 1.15 (2014)
add_project_arguments('-D_DEFAULT_SOURCE', language: 'c')

# Sometimes ignoring the result of read()/write() is the right thing to do
add_project_arguments('-Wno-unused-result', language: 'c')

cc = meson.get_compiler('c')
config_data = configuration_data()

# mention version
version = '"@0@"'.format(meson.project_version())
git = find_program('git', native: true, required: false)
if git.found()
	commit = run_command([git, 'rev-parse', '--verify', '-q', 'HEAD'])
	if commit.returncode() == 0
		version = '"@0@ (commit @1@)"'.format(meson.project_version(), commit.stdout().strip())
	endif
endif
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
	has_dmabuf = true
else
	has_dmabuf = false
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
libva = dependency('libva', required: get_option('with_vaapi'))
if libavcodec.found() and libavutil.found() and libswscale.found()
	config_data.set('HAS_VIDEO', 1, description: 'Enable video (de)compression')
	if libva.found()
		config_data.set('HAS_VAAPI', 1, description: 'Enable hardware video (de)compression with VAAPI')
	endif
endif

waypipe_includes = [include_directories('protocols'), include_directories('src')]
if libdrm.found()
	waypipe_includes += include_directories(libdrm.get_pkgconfig_variable('includedir'))
endif

subdir('protocols')
subdir('src')
subdir('test')

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
