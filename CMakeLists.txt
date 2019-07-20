cmake_minimum_required(VERSION 3.10)

project(funchook C ASM)

set(DISTORM_PATH distorm/)
set(DISTORM_SRC_DIR ${DISTORM_PATH}/src/)
set(DISTORM_SOURCES ${DISTORM_SRC_DIR}/decoder.c ${DISTORM_SRC_DIR}/distorm.c ${DISTORM_SRC_DIR}/instructions.c
        ${DISTORM_SRC_DIR}/insts.c ${DISTORM_SRC_DIR}/mnemonics.c ${DISTORM_SRC_DIR}/operands.c
        ${DISTORM_SRC_DIR}/prefix.c ${DISTORM_SRC_DIR}/textdefs.c ${DISTORM_SRC_DIR}/wstring.c)

add_library(distorm STATIC ${DISTORM_SOURCES})
target_include_directories(distorm PUBLIC ${DISTORM_PATH}/include)

set(FUNCHOOK_SRC_DIR src/)
set(FUNCHOOK_SOURCES src/funchook.c src/funchook_io.c src/funchook_x86.c src/os_func.c src/printf_base.c)
if (MINGW)
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/funchook_windows.c src/os_func_windows.c)
else ()
    set(FUNCHOOK_SOURCES ${FUNCHOOK_SOURCES} src/funchook_unix.c src/os_func_unix.c src/funchook_syscall.S)
endif ()

add_library(funchook STATIC ${FUNCHOOK_SOURCES})
if (MINGW)
    target_link_libraries(funchook PUBLIC distorm psapi)
else ()
    target_link_libraries(funchook PUBLIC distorm dl)
endif ()
target_include_directories(funchook PUBLIC include)