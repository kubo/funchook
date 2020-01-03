cmake_minimum_required(VERSION 3.10)
project(libfunchook_test C ASM)

if (CMAKE_C_FLAGS MATCHES "-m32")
    set(FUNCHOOK_CPU "x86")
else ()
    set(FUNCHOOK_CPU "x86_64")
endif ()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../ ${CMAKE_CURRENT_SOURCE_DIR}/../build)
add_library(funchook_test SHARED libfunchook_test.c)

add_executable(funchook_test_ex test_main.c ${FUNCHOOK_CPU}_test.S)

if (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup")
elseif (UNIX)
    set_target_properties(funchook_test_ex PROPERTIES LINK_FLAGS -rdynamic)
endif ()

target_link_libraries(funchook_test_ex funchook funchook_test)