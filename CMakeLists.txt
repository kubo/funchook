cmake_minimum_required(VERSION 3.5)

project(funchook LANGUAGES C ASM VERSION 1.0.0)

option(FUNCHOOK_BUILD_SHARED "build shared library" ON)
option(FUNCHOOK_BUILD_STATIC "build static library" ON)
option(FUNCHOOK_BUILD_TESTS "Build tests" ON)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE) #used for _sys_nerr and _sys_errlist
  set(_GNU_SOURCE 1)
endif ()

include(CheckSymbolExists)
check_symbol_exists(_sys_nerr "stdio.h" HAVE_DECL__SYS_NERR)
check_symbol_exists(_sys_errlist "stdio.h" HAVE_DECL__SYS_ERRLIST)
check_symbol_exists(sys_nerr "stdio.h" HAVE_DECL_SYS_NERR)
check_symbol_exists(sys_errlist "stdio.h" HAVE_DECL_SYS_ERRLIST)

include(CheckCCompilerFlag)
check_c_compiler_flag(-fvisibility=hidden HAVE_FVISIBILITY_HIDDEN)

#
# distorm
#

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

set(FUNCHOOK_SOURCES src/funchook.c src/funchook_io.c src/funchook_x86.c src/os_func.c src/printf_base.c
    src/funchook_${FUNCHOOK_OS}.c src/os_func_${FUNCHOOK_OS}.c)
if (UNIX)
  set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/funchook_syscall.S)
endif ()

set(FUNCHOOK_PROPERTIES
    OUTPUT_NAME funchook
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    DEFINE_SYMBOL FUNCHOOK_EXPORTS)

set_source_files_properties(src/printf_base.c PROPERTIES COMPILE_FLAGS "-DDPFB_NO_EXTERNAL_FUNC -DPFB_MSVC_FORMAT -DPFB_NO_FLOATING_POINT_FORMAT -DPFB_NO_WIDE_CHAR_FORMAT")
configure_file(src/cmake_config.h.in config.h)

if (FUNCHOOK_BUILD_SHARED)
  add_library(funchook-shared SHARED ${FUNCHOOK_SOURCES})
  set_target_properties(funchook-shared PROPERTIES ${FUNCHOOK_PROPERTIES})
  target_include_directories(funchook-shared PUBLIC include)
  target_include_directories(funchook-shared PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # to include config.h
  target_link_libraries(funchook-shared PRIVATE distorm ${FUNCHOOK_DEPS})
  if (HAVE_FVISIBILITY_HIDDEN)
    target_compile_options(funchook-shared PRIVATE -fvisibility=hidden)
  endif ()
  if (MINGW)
    set_target_properties(funchook-shared PROPERTIES PREFIX "")
  endif ()
  if (MSVC)
    set_target_properties(funchook-shared PROPERTIES IMPORT_SUFFIX _dll.lib)
  endif ()
endif ()

if (FUNCHOOK_BUILD_STATIC)
  add_library(funchook-static STATIC ${FUNCHOOK_SOURCES})
  set_target_properties(funchook-static PROPERTIES ${FUNCHOOK_PROPERTIES})
  target_include_directories(funchook-static PUBLIC include)
  target_include_directories(funchook-static PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # to include config.h
  target_link_libraries(funchook-static PRIVATE distorm ${FUNCHOOK_DEPS})
  if (HAVE_FVISIBILITY_HIDDEN)
    target_compile_options(funchook-static PRIVATE -fvisibility=hidden)
  endif ()
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
