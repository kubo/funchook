cmake_minimum_required(VERSION 3.5)

project(funchook LANGUAGES C ASM)
set(PROJECT_VERSION 1.1.0-dev)
set(PROJECT_VERSION_MAJOR 1)

option(FUNCHOOK_BUILD_SHARED "build shared library" ON)
option(FUNCHOOK_BUILD_STATIC "build static library" ON)
option(FUNCHOOK_BUILD_TESTS "Build tests" ON)
set(FUNCHOOK_DISASM distorm CACHE STRING "disassembler engine")

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(_GNU_SOURCE 1)
  include(CheckCSourceCompiles)
  # musl libc doesn't provide the GNU-specific version of strerror_r
  # even when _GNU_SOURCE is defined.
  check_c_source_compiles(
    "#define _GNU_SOURCE 1
     #include <string.h>
     int main()
     {
         char dummy[128];
         return *strerror_r(0, dummy, sizeof(dummy));
     }
    "
    GNU_SPECIFIC_STRERROR_R
  )
endif ()

include(CheckCCompilerFlag)
check_c_compiler_flag(-fvisibility=hidden HAVE_FVISIBILITY_HIDDEN)

if (FUNCHOOK_DISASM STREQUAL distorm)
  set(DISASM_DISTORM 1)
else ()
  message(FATAL_ERROR "Unknown FUNCHOOK_DISASM type: ${FUNCHOOK_DISASM}")
endif ()

if (CMAKE_TOOLCHAIN_FILE)
  get_filename_component(TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" ABSOLUTE BASE_DIR "${CMAKE_BINARY_DIR}")
else ()
  set(TOOLCHAIN_FILE "")
endif ()

#
# distorm
#
if (DISASM_DISTORM)
  set(DISTORM_PATH distorm/)
  set(DISTORM_SRC_DIR ${DISTORM_PATH}/src/)
  set(DISTORM_SOURCES ${DISTORM_SRC_DIR}/decoder.c ${DISTORM_SRC_DIR}/distorm.c ${DISTORM_SRC_DIR}/instructions.c
      ${DISTORM_SRC_DIR}/insts.c ${DISTORM_SRC_DIR}/mnemonics.c ${DISTORM_SRC_DIR}/operands.c
      ${DISTORM_SRC_DIR}/prefix.c ${DISTORM_SRC_DIR}/textdefs.c ${DISTORM_SRC_DIR}/wstring.c)
  if (MSVC)
    # Suppress warning C4819:
    #   The file contains a character that cannot be represented in the current code
    #   page (number). Save the file in Unicode format to prevent data loss.
    #
    # prefix.c includes non-ascii chracters and C compiler warns C4819 on multibyte Windows
    # environment.
    set_source_files_properties(${DISTORM_SRC_DIR}/prefix.c PROPERTIES COMPILE_FLAGS /wd4819)
  endif ()
  add_library(distorm STATIC ${DISTORM_SOURCES})
  set_target_properties(distorm PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_include_directories(distorm PUBLIC ${DISTORM_PATH}/include)
  if (HAVE_FVISIBILITY_HIDDEN)
    target_compile_options(distorm PRIVATE -fvisibility=hidden)
  endif ()
  set(DISASM distorm)
endif ()

#
# funchook
#

if (WIN32)
  set(FUNCHOOK_OS windows)
  set(FUNCHOOK_DEPS psapi)
else ()
  set(FUNCHOOK_OS unix)
  set(FUNCHOOK_DEPS dl)
endif ()

set(FUNCHOOK_SOURCES src/funchook.c src/funchook_x86.c src/funchook_${FUNCHOOK_OS}.c src/disasm_${DISASM}.c)

set(FUNCHOOK_PROPERTIES
    OUTPUT_NAME funchook
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    DEFINE_SYMBOL FUNCHOOK_EXPORTS)

set_source_files_properties(src/printf_base.c PROPERTIES COMPILE_FLAGS "-DDPFB_NO_EXTERNAL_FUNC -DPFB_MSVC_FORMAT -DPFB_NO_FLOATING_POINT_FORMAT -DPFB_NO_WIDE_CHAR_FORMAT")
configure_file(src/cmake_config.h.in config.h)

function (add_funchook_library target_name target_type)
  add_library(${target_name} ${target_type} ${FUNCHOOK_SOURCES})
  set_target_properties(${target_name} PROPERTIES ${FUNCHOOK_PROPERTIES})
  target_include_directories(${target_name} PUBLIC include)
  target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # to include config.h
  target_link_libraries(${target_name} PRIVATE ${DISASM} ${FUNCHOOK_DEPS})
  if (HAVE_FVISIBILITY_HIDDEN)
    target_compile_options(${target_name} PRIVATE -fvisibility=hidden)
  endif ()
endfunction ()

if (FUNCHOOK_BUILD_SHARED)
  add_funchook_library(funchook-shared SHARED)
  if (MINGW)
    set_target_properties(funchook-shared PROPERTIES PREFIX "")
  endif ()
  if (MSVC)
    set_target_properties(funchook-shared PROPERTIES IMPORT_SUFFIX _dll.lib)
  endif ()
endif ()

if (FUNCHOOK_BUILD_STATIC)
  add_funchook_library(funchook-static STATIC)
endif ()

#
# tests
#

enable_testing()
if (FUNCHOOK_BUILD_TESTS)
  add_subdirectory(test)
endif ()

#
# install
#

include("GNUInstallDirs")

install(FILES include/funchook.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (FUNCHOOK_BUILD_SHARED)
  install(TARGETS funchook-shared
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  if (MSVC)
    install(FILES $<TARGET_PDB_FILE:funchook-shared> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
  endif ()
endif ()

if (FUNCHOOK_BUILD_STATIC)
  install(TARGETS funchook-static
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()
