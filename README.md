Funchook - an API hook library
==============================

This library depends on [diStorm3][].

[![Build Status](https://travis-ci.org/kubo/funchook.svg?branch=master)](https://travis-ci.org/kubo/funchook) [![Build status](https://ci.appveyor.com/api/projects/status/molkbu0csbshbnmh/branch/master?svg=true)](https://ci.appveyor.com/project/kubo/funchook/branch/master)

TODO
----

* write documents.

Supported Platforms
-------------------

* Linux x86_64 (*1)
* Linux x86 (*1)
* OS X x86_64 (*1) (Xcode version <= 10.3(*3))
* OS X x86 (*1) (Xcode version <= 10.1(*4))
* Windows x64 (*2) (except C-runtime functions under [Wine][])
* Windows 32-bit (*2)

*1 tested on [Travis CI](https://travis-ci.org/kubo/funchook)  
*2 tested on [AppVeyor](https://ci.appveyor.com/project/kubo/funchook/branch/master)  
*3 Unit tests pass with xcode 10.3 on macOS 10.14.4 Mojave but fail with xcode 11.0 on the same macOS version. See [here](https://travis-ci.org/kubo/funchook/builds/601220026).  
*4 Xcode 10.2 dropped support for building 32-bit apps.

Compilation
-----------

```shell
$ git clone --recursive https://github.com/kubo/funchook.git
$ cd funchook
$ ./autogen.sh
$ ./configure
$ make
$ make test
```

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

[diStorm3][] has been released under 3-clause BSD since Nov 19, 2016. The
license is compatible with the GPL.

[GPL linking exception]: https://en.wikipedia.org/wiki/GPL_linking_exception
[diStorm3]: https://github.com/gdabah/distorm/
[Wine]: https://www.winehq.org/
