project('hashmap', 'c',
  default_options: [
    'default_library=static',
  ]
)

hashmap_src = files('hashmap.c')
hashmap_inc = include_directories('.')

hashmap_lib = library('hashmap',
  hashmap_src,
  include_directories: hashmap_inc,
  c_args: ['-DHM_DLL', '-DHM_IMPL'],
)

hashmap_exe = executable('hashmap_test',
  hashmap_src,
  include_directories: hashmap_inc,
  c_args: '-DHASHMAP_TEST',
)

hashmap_dep = declare_dependency(
  link_with: hashmap_lib,
  include_directories: hashmap_inc,
  compile_args: ['-DHM_DLL'],
)

if meson.version().version_compare('>= 0.54.0')
  meson.override_dependency('hashmap', hashmap_dep)
endif

test('test', hashmap_exe)
test('bench', hashmap_exe, env: ['BENCH=1'])
