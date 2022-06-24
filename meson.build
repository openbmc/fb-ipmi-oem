project(
  'fb-ipmi-oem',
  'cpp',
  version: '0.1',
  meson_version: '>=0.57.0',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++20',
  ])

# Project Arguments
cpp = meson.get_compiler('cpp')
add_project_arguments(
  cpp.get_supported_arguments([
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    '-Wno-psabi',
    '-Wno-pedantic',
  ]),
  language : 'cpp')

host_instances = '0'
if get_option('host-instances') != ''
  host_instances = get_option('host-instances')
endif

add_project_arguments(
  cpp.get_supported_arguments([
    '-DINSTANCES=' + host_instances,
  ]),
  language : 'cpp')

if not get_option('bic').disabled()
  add_project_arguments(
    cpp.get_supported_arguments([
        '-DBIC_ENABLED',
    ]),
    language : 'cpp')
endif

root_inc = include_directories('.', 'include')

# Dependencies
phosphor_logging_dep = dependency('phosphor-logging')
sdbusplus_dep = dependency('sdbusplus', required : false, include_type: 'system')
ipmid_dep = dependency('libipmid')
channellayer_dep = cpp.find_library('channellayer', required: true)
userlayer_dep = cpp.find_library('userlayer', required: true)

zfboemcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    phosphor_logging_dep,
    sdbusplus_dep,
    ipmid_dep,
    channellayer_dep,
    userlayer_dep,
  ])

zfboemcmds_lib = library(
  'zfboemcmds',
  'src/oemcommands.cpp',
  'src/appcommands.cpp',
  'src/storagecommands.cpp',
  'src/usb-dbg.cpp',
  'src/selcommands.cpp',
  'src/transportcommands.cpp',
  'src/biccommands.cpp',
  implicit_include_directories: false,
  dependencies: zfboemcmds_pre,
  version: meson.project_version(),
  override_options: ['b_lundef=false'],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers')
