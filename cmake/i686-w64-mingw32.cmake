set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR i686)
set(TOOLCHAIN_PREFIX i686-w64-mingw32)

# cross compilers to use for C and C++
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)

# target environment on the build host system
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})

set(CMAKE_C_FLAGS "-D_WIN32_WINNT=0x600 -m32 -static-libgcc" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "-m32" CACHE STRING "" FORCE)
