Funchook - an API hook library
==============================

[![Build Status](https://travis-ci.org/kubo/funchook.svg?branch=master)](https://travis-ci.org/kubo/funchook)

This library depends on one of the following disassemblers.

On x86_64 and x86
* [diStorm3][] (default)
* [zydis][] (when `-DFUNCHOOK_DISASM=zydis` is passed to the `cmake` command)
* [capstone][] (when `-DFUNCHOOK_DISASM=capstone` is passed to the `cmake` command)

On arm64
* [capstone][]

TODO
----

* write documents.

News
----

### 1.1.0 (2020-03-22)

* Arm64 Linux support. [capstone][] is used as the disassembler library on arm64.
* Options to use [zydis][] and [capstone][] as a disassembler library on x86_64 and x86.
* `extern "C"` was added in funchook.h for C++. ([#15][])
* Libc-compatible functions were removed to simplify code.

### 1.0.0 (2020-01-19)

* [diStorm3][] is used as the disassembler library.
* Libc-compatible functions were implemented on Linux in order not to hook function calls issued by funchook itself.

Supported Platforms
-------------------

Tested on [Travis CI](https://travis-ci.org/kubo/funchook)  

* Linux x86_64
* Linux x86
* Linux arm64 (since 1.1.0)
* macOS x86_64 (Functions in executables cannot be hooked when Xcode version >= 11.0. (*1))
* macOS x86 (Xcode version <= 10.1(*2))
* Windows x64 (except C-runtime functions under [Wine][])
* Windows 32-bit

*1 [`mprotect`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mprotect.2.html) fails with EACCES.  
*2 Xcode 10.2 dropped support for building 32-bit apps.  

Compilation and installation
-----------

### Unix

```shell
$ git clone --recursive https://github.com/kubo/funchook.git
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/path/to/install/directory ../funchook
$ make
$ make install
```

* Available [`CMAKE_BUILD_TYPE`][] values are empty(default), `Debug`, `Release`, `RelWithDebInfo`(release build with debug information) and `MinSizeRel`.
* When [`CMAKE_INSTALL_PREFIX`][] isn't set, funchook is installed at `/usr/local`.

  installed files:
  * `${CMAKE_INSTALL_PREFIX}/include/funchook.h` (header file)
  * `${CMAKE_INSTALL_PREFIX}/lib/libfunchook.so` (symbolic link to `libfunchook.so.1`)
  * `${CMAKE_INSTALL_PREFIX}/lib/libfunchook.so.1` ([soname][]; symbolic link to `libfunchook.so.1.1.0`)
  * `${CMAKE_INSTALL_PREFIX}/lib/libfunchook.so.1.1.0` (shared library)
  * `${CMAKE_INSTALL_PREFIX}/lib/libfunchook.a` (static library)

### Windows

Here is an example to compile funchook with Visual Studio 2017 Win64.
Change the argument of `-G` to use other compilers.

```shell
$ git clone --recursive https://github.com/kubo/funchook.git
$ mkdir build
$ cd build
$ cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX=c:\path\to\install\directory ..\funchook
$ cmake --build . --config Release --target INSTALL
```

* Available `-G` arguments (generators) are listed in the output of `cmake --help`.
* Available `--config` arguments are `Debug`(default), `Release`, `RelWithDebInfo` and `MinSizeRel`.
* When [`CMAKE_INSTALL_PREFIX`][] isn't set, funchook is installed at `c:\Program Files\funchook`.

  installed files:
  * `${CMAKE_INSTALL_PREFIX}\include\funchook.h` (header file)
  * `${CMAKE_INSTALL_PREFIX}\bin\funchook.dll` (shared library)
  * `${CMAKE_INSTALL_PREFIX}\bin\funchook.pdb` (debug file for `funchook.dll` when `--config` is `Debug` or `RelWithDebInfo`)
  * `${CMAKE_INSTALL_PREFIX}\lib\funchook.lib` (static library)
  * `${CMAKE_INSTALL_PREFIX}\lib\funchook_dll.lib` (import library for `funchook.dll`)

Example
-------

```c
static ssize_t (*send_func)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*recv_func)(int sockfd, void *buf, size_t len, int flags);

static ssize_t send_hook(int sockfd, const void *buf, size_t len, int flags);
{
    ssize_t rv;

    ... do your task: logging, etc. ...
    rv = send_func(sockfd, buf, len, flags); /* call the original send(). */
    ... do your task: logging, checking the return value, etc. ...
    return rv;
}

static ssize_t recv_hook(int sockfd, void *buf, size_t len, int flags);
{
    ssize_t rv;

    ... do your task: logging, etc. ...
    rv = recv_func(sockfd, buf, len, flags); /* call the original recv(). */
    ... do your task: logging, checking received data, etc. ...
    return rv;
}

int install_hooks()
{
    funchook_t *funchook = funchook_create();
    int rv;

    /* Prepare hooking.
     * The return value is used to call the original send function
     * in send_hook.
     */
    send_func = send;
    rv = funchook_prepare(funchook, (void**)&send_func, send_hook);
    if (rv != 0) {
       /* error */
       ...
    }

    /* ditto */
    recv_func = recv;
    rv = funchook_prepare(funchook, (void**)&recv_func, recv_hook);
    if (rv != 0) {
       /* error */
       ...
    }

    /* Install hooks.
     * The first 5-byte code of send() and recv() are changed respectively.
     */
    rv = funchook_install(funchook, 0);
    if (rv != 0) {
       /* error */
       ...
    }
}

```

License
-------

GPLv2 or later with a [GPL linking exception][].

You can use funchook in any software. Though funchook is licensed under
the GPL, it doesn't affect outside of funchook due to the linking exception.
You have no need to open your souce code under the GPL except funchook itself.

If you modify funchook itself and release it, the modifed part must be
open under the GPL with or without the linking exception because funchook
itself is under the GPL.

[diStorm3][] and [capstone][] are released under the 3-clause BSD license.
[zydis][] is released under the MIT license. They are compatible with the GPL.

[GPL linking exception]: https://en.wikipedia.org/wiki/GPL_linking_exception
[diStorm3]: https://github.com/gdabah/distorm/
[zydis]: https://github.com/zyantific/zydis
[capstone]: https://github.com/aquynh/capstone
[Wine]: https://www.winehq.org/
[`CMAKE_BUILD_TYPE`]: https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html
[`CMAKE_INSTALL_PREFIX`]: https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html
[soname]: https://en.wikipedia.org/wiki/Soname
[#15]: https://github.com/kubo/funchook/issues/15
