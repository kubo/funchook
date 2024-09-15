project(
  'funchook',
  'c',
  version: '2.0.0',
  # Nearly Classpath-exception-2.0, but not exactly. Additional clause:
  # "If you modify this library, you must extend this exception to
  # your version of the library."
  license: 'GPL-2.0-or-later WITH Classpath-exception-2.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
  ],
  meson_version: '>=1.2',
)

cc = meson.get_compiler('c')

host_cpu_family = host_machine.cpu_family()

if host_cpu_family in ['x86', 'x86_64']
  funchook_cpu = 'x86'
  default_disasm = 'Zydis'
elif host_cpu_family == 'aarch64'
  funchook_cpu = 'arm64'
  default_disasm = 'capstone'
endif

host_system = host_machine.system()

funchook_deps = []
cdata = configuration_data()

if host_system in ['windows', 'cygwin']
  funchook_os = 'windows'
  funchook_deps += cc.find_library('psapi')
else
  funchook_os = 'unix'
  funchook_deps += dependency('dl')
endif

if host_machine.system() == 'linux'
  add_project_arguments(
    '-D_GNU_SOURCE',
    language: 'c',
  )
  # musl libc doesn't provide the GNU-specific version of strerror_r
  # even when _GNU_SOURCE is defined.
  gnu_strerror_r = cc.compiles(
    '''
    #define _GNU_SOURCE
    #include <string.h>
    int main()
    {
      char dummy[128];
      return *strerror_r(0, dummy, sizeof(dummy));
    }
    ''',
  )
  cdata.set10('GNU_SPECIFIC_STRERROR_R', gnu_strerror_r)
endif

disasm = get_option('disasm')
if disasm == 'auto'
  funchook_disasm = default_disasm
else
  funchook_disasm = disasm
endif

if funchook_disasm == 'Zydis'
  funchook_deps += dependency(
    'zydis',
    version: '>=4.0.0',
    default_options: {
      'minimal': 'enabled',
      'decoder': 'enabled',
    },
  )
  cdata.set10('DISASM_ZYDIS', true)
elif disasm == 'capstone'
  funchook_deps += dependency(
    'capstone',
    version: '>=5.0.0',
    default_options: {
      'archs': [funchook_cpu],
      'x86_reduce': true,
      'x86_att_disable': true,
    },
  )
  cdata.set10('DISASM_CAPSTONE', true)
endif

sizeof_void_p = cc.sizeof('void*')
cdata.set('SIZEOF_VOID_P', sizeof_void_p)

configure_file(
  output: 'config.h',
  configuration: cdata,
)

hdrs = files(
  'include/funchook.h',
)

src = files(
  'src/funchook.c',
  f'src/arch_@funchook_cpu@.c',
  f'src/os_@funchook_os@.c',
  f'src/disasm_@funchook_disasm@.c',
)

extra_masmflags = []

if funchook_cpu == 'x86' and sizeof_void_p == 8
  if cc.get_id() == 'msvc' and add_languages('masm', native: false)
    prehook = 'prehook-x86_64-ms'
    src += configure_file(
      input: 'src' / f'@prehook@.asm',
      output: f'@prehook@.masm',
      copy: true,
    )
  elif funchook_os == 'windows'
    src += files('src/prehook-x86_64-ms.S')
  else
    src += files('src/prehook-x86_64-sysv.S')
  endif
endif

if funchook_cpu == 'x86' and sizeof_void_p == 4
  if cc.get_id() == 'msvc' and add_languages('masm', native: false)
    prehook = 'prehook-i686-ms'
    src += configure_file(
      input: 'src' / f'@prehook@.asm',
      output: f'@prehook@.masm',
      copy: true,
    )
    extra_masmflags += '/safeseh'
  else
    src += files('src/prehook-i686-gas.S')
  endif
endif

if funchook_cpu == 'arm64'
  if cc.get_id() == 'msvc' and add_languages('masm', native: false)
    prehook = 'prehook-arm64-ms'
    src += configure_file(
      input: 'src' / f'@prehook@.asm',
      output: f'@prehook@.masm',
      copy: true,
    )
  else
    src += files('src/prehook-arm64-gas.S')
  endif
endif

inc = include_directories('include')

funchook_lib = library(
  'funchook',
  src,
  include_directories: inc,
  dependencies: funchook_deps,
  masm_args: extra_masmflags,
  version: meson.project_version(),
  install: true,
)

install_headers(hdrs)

funchook_dep = declare_dependency(
  link_with: funchook_lib,
  include_directories: inc,
)

pkg = import('pkgconfig')
pkg.generate(
  funchook_lib,
  name: 'funchook',
  description: 'Cross platform inline hooking library',
  url: 'https://github.com/kubo/funchook',
)

meson.override_dependency('funchook', funchook_dep)
