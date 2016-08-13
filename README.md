Duckhook - an API hook library
==============================

This library depends on [diStorm3][].

[![Build Status](https://travis-ci.org/kubo/duckhook.svg?branch=master)](https://travis-ci.org/kubo/duckhook) [![Build status](https://ci.appveyor.com/api/projects/status/aqn59yiyy0vst5kg/branch/master?svg=true)](https://ci.appveyor.com/project/kubo/duckhook/branch/master)

TODO
----

* write documents.

Supported Platform
-----------------

* Linux x86_64 (*1)
* Linux x86 (*1)
* OS X x86_64 (*1)
* OS X x86 (*1)
* Windows x64 (*2)
* Windows 32-bit (*2)

*1 tested on [Travis CI](https://travis-ci.org/kubo/duckhook)  
*2 tested on [AppVeyor](https://ci.appveyor.com/project/kubo/duckhook/branch/master)

Compilation
-----------

```shell
$ git clone https://github.com/kubo/duckhook.git
$ git submodule init
$ git submodule update # clone diStorm3
$ cd src
$ make
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
    duckhook_t *duckhook = duckhook_create();
    int rv;

    /* Prepare hooking.
     * The return value is used to call the original send function
     * in send_hook.
     */
    send_func = send;
    rv = duckhook_prepare(duckhook, (void**)&send_func, send_hook);
    if (rv != 0) {
       /* error */
       ...
    }

    /* ditto */
    recv_func = recv;
    rv = duckhook_prepare(duckhook, (void**)&recv_func, recv_hook);
    if (rv != 0) {
       /* error */
       ...
    }

    /* Install hooks.
     * The first 5-byte code of send() and recv() are changed respectively.
     */
    rv = duckhook_install(duckhook, 0);
    if (rv != 0) {
       /* error */
       ...
    }
}

```

License
-------

GPLv2 or later with a [GPL linking exception][].

You can use duckhook in any software. Though duckhook is licensed under
the GPL, it doesn't affect outside of duckhook due to the linking exception.
You have no need to open your souce code under the GPL except duckhook itself.

If you modify duckhook itself and release it, the modifed part must be
open under the GPL with or without the linking exception because duckhook
itself is under the GPL.

If you use duckhook in GPL'ed software, you need to use [diStorm3][]
before [May 29, 2016][]. The license of [diStorm3][] was changed from the
GPLv3 to 4-clause BSD license at that time. However 4-clause BSD license
is [incompatible with the GPL][GPL-incompatibility].

[GPL linking exception]: https://en.wikipedia.org/wiki/GPL_linking_exception
[diStorm3]: https://github.com/gdabah/distorm/
[GPL-incompatibility]: https://www.gnu.org/licenses/license-list.html#OriginalBSD
[May 29, 2016]: https://github.com/gdabah/distorm/commit/938e6ace4afdbc8b7b6f83d03efcd00dd52301e6
