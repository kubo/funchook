# GIT_SHALLOW requires cmake 3.6.
cmake_minimum_required(VERSION 3.6)

project(funchook LANGUAGES C ASM)
set(PROJECT_VERSION 1.1.0)
set(PROJECT_VERSION_MAJOR 1)

include("GNUInstallDirs")

if(NOT FUNCHOOK_CPU) 
  set(FUNCHOOK_CPU ${CMAKE_SYSTEM_PROCESSOR})
  if (FUNCHOOK_CPU STREQUAL x86_64 OR FUNCHOOK_CPU MATCHES "i.86" OR FUNCHOOK_CPU STREQUAL AMD64)
      set(FUNCHOOK_CPU x86)
  endif ()
  if (FUNCHOOK_CPU STREQUAL aarch64)
      set(FUNCHOOK_CPU arm64)
  endif ()
endif ()

if (FUNCHOOK_CPU STREQUAL arm64)
  set(FUNCHOOK_DEFAULT_DISASM "capstone")
else ()
  set(FUNCHOOK_DEFAULT_DISASM "distorm")
endif ()

option(FUNCHOOK_BUILD_SHARED "build shared library" ON)
option(FUNCHOOK_BUILD_STATIC "build static library" ON)
option(FUNCHOOK_BUILD_TESTS "Build tests" ON)
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

#
# capstone
#
if (DISASM_CAPSTONE)
  set(CAPSTONE_arm64_SUPPORT OFF)
  set(CAPSTONE_x86_SUPPORT OFF)
  set(CAPSTONE_${FUNCHOOK_CPU}_SUPPORT ON)

  include(ExternalProject)
  ExternalProject_Add(capstone_src
    GIT_REPOSITORY    https://github.com/aquynh/capstone.git
    GIT_TAG           4.0.1
    GIT_SHALLOW       TRUE
    CMAKE_ARGS        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                      -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}
                      -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                      -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
                      -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
                      -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                      -DCAPSTONE_BUILD_SHARED=OFF
                      -DCAPSTONE_BUILD_STATIC_RUNTIME=OFF
                      -DCAPSTONE_BUILD_TESTS=OFF
                      -DCAPSTONE_BUILD_CSTOOL=OFF
                      -DCAPSTONE_ARM_SUPPORT=OFF
                      -DCAPSTONE_ARM64_SUPPORT=${CAPSTONE_arm64_SUPPORT}
                      -DCAPSTONE_EVM_SUPPORT=OFF
                      -DCAPSTONE_M680X_SUPPORT=OFF
                      -DCAPSTONE_M68K_SUPPORT=OFF
                      -DCAPSTONE_MIPS_SUPPORT=OFF
                      -DCAPSTONE_PPC_SUPPORT=OFF
                      -DCAPSTONE_SPARC_SUPPORT=OFF
                      -DCAPSTONE_SYSZ_SUPPORT=OFF
                      -DCAPSTONE_TMS320C64X_SUPPORT=OFF
                      -DCAPSTONE_XCORE_SUPPORT=OFF
                      -DCAPSTONE_X86_SUPPORT=${CAPSTONE_x86_SUPPORT}
    INSTALL_COMMAND   ${CMAKE_COMMAND} --build . --target install
  )
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include)
  add_library(capstone STATIC IMPORTED)
  set_property(TARGET capstone PROPERTY IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
  set_property(TARGET capstone PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/include)
  list(APPEND FUNCHOOK_DEPS capstone)
  set(DISASM capstone)
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
  list(APPEND FUNCHOOK_DEPS distorm)
endif ()

#
# zydis
#
if (DISASM_ZYDIS)
  include(ExternalProject)
  ExternalProject_Add(Zydis_src
    GIT_REPOSITORY    https://github.com/zyantific/zydis.git
    GIT_TAG           v3.1.0
    GIT_SHALLOW       TRUE
    CMAKE_ARGS        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                      -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_FILE}
                      -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                      -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
                      -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}
                      -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                      -DZYDIS_BUILD_SHARED_LIB=OFF
                      -DZYDIS_BUILD_EXAMPLES=OFF
                      -DZYDIS_BUILD_TOOLS=OFF
    INSTALL_COMMAND  ${CMAKE_COMMAND} --build . --target install && ${CMAKE_COMMAND} --build zycore --target install
  )
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include)
  add_library(Zydis STATIC IMPORTED)
  set_property(TARGET Zydis PROPERTY IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}Zydis${CMAKE_STATIC_LIBRARY_SUFFIX})
  set_property(TARGET Zydis PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/include)
  list(APPEND FUNCHOOK_DEPS Zydis)
  set(DISASM Zydis)
endif ()

#
# funchook
#

set(FUNCHOOK_SOURCES src/funchook.c src/funchook_${FUNCHOOK_CPU}.c src/funchook_${FUNCHOOK_OS}.c src/disasm_${DISASM}.c)

set(FUNCHOOK_PROPERTIES
    OUTPUT_NAME funchook
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    DEFINE_SYMBOL FUNCHOOK_EXPORTS)

configure_file(src/cmake_config.h.in config.h)

function (add_funchook_library target_name target_type)
  add_library(${target_name} ${target_type} ${FUNCHOOK_SOURCES})
  if (NOT DISASM STREQUAL distorm)
    add_dependencies(${target_name} ${DISASM}_src)
  endif ()
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
