cmake_minimum_required(VERSION 3.10)

project(distorm C ASM)

if (NOT DEFINED BUILD_SHARED_LIBS)
    set(BUILD_SHARED_LIBS ON)
endif ()

set(DISTORM_PATH distorm/)
set(DISTORM_SRC_DIR ${DISTORM_PATH}/src/)
set(DISTORM_SOURCES ${DISTORM_SRC_DIR}/decoder.c ${DISTORM_SRC_DIR}/distorm.c ${DISTORM_SRC_DIR}/instructions.c
        ${DISTORM_SRC_DIR}/insts.c ${DISTORM_SRC_DIR}/mnemonics.c ${DISTORM_SRC_DIR}/operands.c
        ${DISTORM_SRC_DIR}/prefix.c ${DISTORM_SRC_DIR}/textdefs.c ${DISTORM_SRC_DIR}/wstring.c)

add_library(distorm STATIC ${DISTORM_SOURCES})
set_target_properties(distorm PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(distorm PUBLIC ${DISTORM_PATH}/include)

if (MINGW)
    find_library(PSAPI psapi)
    set(FUNCHOOK_DEPS psapi)
    set(FUNCHOOK_OS windows)
else ()
    set(FUNCHOOK_OS unix)
    set(FUNCHOOK_DEPS dl)
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE) #used for _sys_nerr and _sys_errlist
endif ()

include(CheckSymbolExists)

check_symbol_exists(_sys_nerr "stdio.h" HAVE_DECL__SYS_NERR)
check_symbol_exists(_sys_errlist "stdio.h" HAVE_DECL__SYS_ERRLIST)
check_symbol_exists(sys_nerr "stdio.h" HAVE_DECL_SYS_NERR)
check_symbol_exists(sys_errlist "stdio.h" HAVE_DECL_SYS_ERRLIST)

set(FUNCHOOK_SRC_DIR src/)
set(FUNCHOOK_SOURCES src/funchook.c src/funchook_io.c src/funchook_x86.c src/os_func.c src/printf_base.c
        src/funchook_${FUNCHOOK_OS}.c src/os_func_${FUNCHOOK_OS}.c)

if (UNIX)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/funchook_syscall.S)
endif ()

set_source_files_properties(src/printf_base.c PROPERTIES COMPILE_FLAGS "-DPFB_NO_EXTERNAL_FUNC -DPFB_MSVC_FORMAT")

if (BUILD_SHARED_LIBS)
    set(FUNCHOOK_LINKING SHARED)
else ()
    set(FUNCHOOK_LINKING STATIC)
endif ()

add_library(funchook ${FUNCHOOK_LINKING} ${FUNCHOOK_SOURCES})
foreach (HAVE_DECL HAVE_DECL__SYS_NERR HAVE_DECL__SYS_ERRLIST HAVE_DECL_SYS_NERR HAVE_DECL_SYS_ERRLIST)
    if (${HAVE_DECL})
        set_property(TARGET funchook APPEND PROPERTY COMPILE_DEFINITIONS ${HAVE_DECL}=1)
    endif ()
endforeach ()
target_link_libraries(funchook PUBLIC distorm ${FUNCHOOK_DEPS})
target_include_directories(funchook PUBLIC include)