cmake_minimum_required(VERSION 3.11)

project(funchook VERSION 2.0.0 LANGUAGES C ASM)

include("GNUInstallDirs")
include(FetchContent)

if(NOT FUNCHOOK_CPU) 
  set(FUNCHOOK_CPU ${CMAKE_SYSTEM_PROCESSOR})
  if (FUNCHOOK_CPU MATCHES "x86_64" OR FUNCHOOK_CPU MATCHES "i.86" OR FUNCHOOK_CPU MATCHES "AMD64")
      set(FUNCHOOK_CPU x86)
  endif ()
  if (FUNCHOOK_CPU MATCHES "aarch64")
      set(FUNCHOOK_CPU arm64)
  endif ()
  if (FUNCHOOK_CPU MATCHES "ARM64")
      set(FUNCHOOK_CPU arm64)
  endif ()
endif ()

if (FUNCHOOK_CPU MATCHES "arm64")
  set(FUNCHOOK_DEFAULT_DISASM "capstone")
  if (MSVC)
    cmake_minimum_required(VERSION 3.26)
  endif ()
else ()
  set(FUNCHOOK_DEFAULT_DISASM "distorm")
endif ()

option(FUNCHOOK_BUILD_SHARED "build shared library" ON)
option(FUNCHOOK_BUILD_STATIC "build static library" ON)
option(FUNCHOOK_BUILD_TESTS "Build tests" ON)
option(FUNCHOOK_INSTALL "Install Funchook" ON)
set(FUNCHOOK_DISASM ${FUNCHOOK_DEFAULT_DISASM} CACHE STRING "disassembler engine")

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

if (FUNCHOOK_DISASM STREQUAL capstone)
  set(DISASM_CAPSTONE 1)
elseif (FUNCHOOK_DISASM STREQUAL distorm)
  set(DISASM_DISTORM 1)
elseif (FUNCHOOK_DISASM STREQUAL zydis)
  set(DISASM_ZYDIS 1)
else ()
  message(FATAL_ERROR "Unknown FUNCHOOK_DISASM type: ${FUNCHOOK_DISASM}")
endif ()

if (CMAKE_TOOLCHAIN_FILE)
  get_filename_component(TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" ABSOLUTE BASE_DIR "${CMAKE_BINARY_DIR}")
else ()
  set(TOOLCHAIN_FILE "")
endif ()

if (WIN32)
  set(FUNCHOOK_OS windows)
  set(FUNCHOOK_DEPS psapi)
else ()
  set(FUNCHOOK_OS unix)
  set(FUNCHOOK_DEPS dl)
endif ()

function(add_subdirectory_pic source_dir binary_dir)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  add_subdirectory(${source_dir} ${binary_dir})
endfunction(add_subdirectory_pic)

#
# capstone
#
if (DISASM_CAPSTONE)
  FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.1
    GIT_SHALLOW    TRUE
  )
  FetchContent_GetProperties(capstone)
  if(NOT capstone_POPULATED)
    FetchContent_Populate(capstone)
    string(TOUPPER ${FUNCHOOK_CPU} FUNCHOOK_CPU_UPPER)
    set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "")
    set(CAPSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "")
    set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "")
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "")
    set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "")
    set(CAPSTONE_${FUNCHOOK_CPU_UPPER}_SUPPORT ON CACHE BOOL "")
    add_subdirectory_pic(${capstone_SOURCE_DIR} ${capstone_BINARY_DIR})
  endif()

  list(APPEND FUNCHOOK_DEPS capstone)
  set(DISASM capstone)
endif ()

#
# distorm
#
if (DISASM_DISTORM)
  FetchContent_Declare(
    distorm
    GIT_REPOSITORY https://github.com/gdabah/distorm.git
    GIT_TAG        3.5.2b
    GIT_SHALLOW    TRUE
  )
  FetchContent_GetProperties(distorm)
  if(NOT distorm_POPULATED)
    FetchContent_Populate(distorm)

    file(GLOB distorm_SRC_FILES ${distorm_SOURCE_DIR}/src/*.c)
    add_library(distorm STATIC ${distorm_SRC_FILES})
    set_target_properties(distorm PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_include_directories(distorm PUBLIC ${distorm_SOURCE_DIR}/include)
    if (HAVE_FVISIBILITY_HIDDEN)
      target_compile_options(distorm PRIVATE -fvisibility=hidden)
    endif ()
    if (MSVC)
      # workaround for https://github.com/gdabah/distorm/pull/179
      set_source_files_properties(${distorm_SOURCE_DIR}/src/prefix.c PROPERTIES COMPILE_FLAGS /wd4819)
    endif ()
  endif()

  list(APPEND FUNCHOOK_DEPS distorm)
  set(DISASM distorm)
endif ()

#
# zydis
#
if (DISASM_ZYDIS)
  FetchContent_Declare(
    Zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.0.0
    GIT_SHALLOW    TRUE
  )
  FetchContent_GetProperties(Zydis)
  if(NOT zydis_POPULATED)
    FetchContent_Populate(Zydis)
    set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "")
    set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "")
    set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "")
    add_subdirectory_pic(${zydis_SOURCE_DIR} ${zydis_BINARY_DIR})
  endif()

  list(APPEND FUNCHOOK_DEPS Zydis)
  set(DISASM Zydis)
endif ()

#
# funchook
#

set(FUNCHOOK_SOURCES src/funchook.c src/arch_${FUNCHOOK_CPU}.c src/os_${FUNCHOOK_OS}.c src/disasm_${DISASM}.c)

if ((FUNCHOOK_CPU STREQUAL x86) AND (CMAKE_SIZEOF_VOID_P EQUAL "8"))
  if (MSVC)
    # Microsoft x64 calling convention (Microsoft Visual C++)
    enable_language(ASM_MASM)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-x86_64-ms.asm)
  elseif (WIN32)
    # Microsoft x64 calling convention (Mingw-w64)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-x86_64-ms.S)
  else ()
    # System V ABI (Linux, macOS)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-x86_64-sysv.S)
  endif ()
endif ()

if ((FUNCHOOK_CPU STREQUAL x86) AND (CMAKE_SIZEOF_VOID_P EQUAL "4"))
  if (MSVC)
    # Windows (Microsoft Visual C++)
    enable_language(ASM_MASM)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-i686-ms.asm)
    set_source_files_properties(src/prehook-i686-ms.asm PROPERTIES COMPILE_OPTIONS "/safeseh")
  else ()
    # Windows and Linux (gcc)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-i686-gas.S)
  endif ()
endif ()

if (FUNCHOOK_CPU STREQUAL "arm64")
  if (MSVC)
    enable_language(ASM_MARMASM)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-arm64-ms.asm)
  else ()
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/prehook-arm64-gas.S)
  endif ()
endif ()

set(FUNCHOOK_PROPERTIES
    OUTPUT_NAME funchook
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    DEFINE_SYMBOL FUNCHOOK_EXPORTS)

configure_file(src/cmake_config.h.in config.h)

function (add_funchook_library target_name target_type)
  add_library(${target_name} ${target_type} ${FUNCHOOK_SOURCES})
  set_target_properties(${target_name} PROPERTIES ${FUNCHOOK_PROPERTIES})
  target_include_directories(${target_name} PUBLIC include)
  target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # to include config.h
  target_link_libraries(${target_name} PRIVATE ${FUNCHOOK_DEPS})
  if (HAVE_FVISIBILITY_HIDDEN)
    target_compile_options(${target_name} PRIVATE -fvisibility=hidden)
  endif ()
  if (CMAKE_COMPILER_IS_GNUCC)
    target_compile_options(${target_name} PRIVATE -Wall)
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

if (FUNCHOOK_INSTALL)
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
endif ()
