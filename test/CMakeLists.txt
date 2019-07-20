cmake_minimum_required(VERSION 3.10)
project(libfunchook_test C ASM)

if (${CMAKE_C_FLAGS} MATCHES "-m32")
    set(CMAKE_ASM_FLAGS "-m32")
    set(FUNCHOOK_TEST "x86_test.S")
else ()
    set(FUNCHOOK_TEST "x86_64_test.S")
endif ()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../ ${CMAKE_CURRENT_SOURCE_DIR}/../build)
add_library(funchook_test SHARED libfunchook_test.c libfunchook_test2.c)
if (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup")
endif ()

add_executable(funchook_test_ex test_main.c ${FUNCHOOK_TEST})
target_link_libraries(funchook_test_ex funchook_test funchook m)