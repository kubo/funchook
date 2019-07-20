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
set(FUNCHOOK_SOURCES src/funchook.c src/funchook_io.c src/funchook_x86.c src/os_func.c src/printf_base.c
        src/funchook_unix.c src/os_func_unix.c src/funchook_syscall.S)

add_library(funchook STATIC ${FUNCHOOK_SOURCES})
target_link_libraries(funchook PUBLIC distorm dl)
target_include_directories(funchook PUBLIC include)