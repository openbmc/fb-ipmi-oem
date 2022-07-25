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

fs = import('fs')

host_instances = '0'
if get_option('host-instances') != ''
  host_instances = get_option('host-instances')
endif

conf_data = configuration_data()
conf_data.set_quoted('INSTANCES',host_instances)

configure_file(input: 'meson_config.h.in',
               output: 'config.h',
               configuration: conf_data)

if not get_option('bic').disabled()
  add_project_arguments(
    cpp.get_supported_arguments([
        '-DBIC_ENABLED',
    ]),
    language : 'cpp')
endif

root_inc = include_directories('.', 'include')

# Dependencies
sdbusplus_dep = dependency('sdbusplus')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
ipmid_dep = dependency('libipmid')
channellayer_dep = dependency('libchannellayer')
userlayer_dep = dependency('libuserlayer')

if cpp.has_header_symbol(
        'nlohmann/json.hpp',
        'nlohmann::json::string_t',
        required:false)
    nlohmann_json_dep = declare_dependency()
else
    nlohmann_json_dep = dependency('nlohmann-json')
endif

zfboemcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    channellayer_dep,
    ipmid_dep,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
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

if get_option('machine') != ''
  configfile = [
        'cri_sensors.json',
        'gpio_desc.json',
        'post_desc.json'
   ]
   foreach c : configfile
      file = join_paths('configs', get_option('machine'), c)
      if not fs.is_file(file)
         warning('Missing config file: ' + file)
      else
          install_data(
              sources : file,
              install_dir : get_option('datadir') / 'lcd-debug'
          )
      endif
   endforeach
endif
