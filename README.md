Duckhook - an API hook library
==============================

Note: This is unstable. Some functions may be changed.

This library depends on [diStorm3][].

TODO
----

* write documents.
* add a function to get the error reason when `duckhook_prepare` returns NULL.
* add a function to debug duckhook itself.
* add tests.

Supported Platform
-----------------

* Linux x86_64
* Linux 32-bit
* Windows x64 (*1)
* Windows 32-bit (*1)

*1 compiled by mingw-w64 and tested on Wine. I haven't tested it on Windows yet.

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
static ssize_t (*send_orig)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*recv_orig)(int sockfd, void *buf, size_t len, int flags);

static ssize_t send_hook(int sockfd, const void *buf, size_t len, int flags);
{
    ssize_t rv;

    ... do your task: logging, etc. ...
    rv = send_orig(sockfd, buf, len, flags); /* call the original send(). */
    ... do your task: logging, checking the return value, etc. ...
    return rv;
}

static ssize_t recv_hook(int sockfd, void *buf, size_t len, int flags);
{
    ssize_t rv;

    ... do your task: logging, etc. ...
    rv = recv_orig(sockfd, buf, len, flags); /* call the original recv(). */
    ... do your task: logging, checking received data, etc. ...
    return rv;
}

int install_hooks()
{
    duckhook_t *duckhook = duckhook_create();

    /* Prepare hooking.
     * The return value is used to call the original send function
     * in send_hook.
     */
    send_orig = duckhook_prepare(duckhook, send, send_hook);
    if (send_orig == NULL) {
       /* error */
       ...
    }

    /* ditto */
    recv_orig = duckhook_prepare(duckhook, recv, recv_hook);
    if (recv_orig == NULL) {
       /* error */
       ...
    }

    /* Install hooks.
     * The first 5-byte code of send() and recv() are changed respectively.
     */
    int rv = duckhook_install(duckhook, 0);
    if (rv != 0) {
       /* error */
       ...
    }
}

```

License
-------

GPLv2 or later with a [GPL linking exception][].

You can use Duckhook in any software as long as the software
doesn't forbid API hooking. However if you modify Duckhook
itself, the modifed part must be under the GPL with or without
the linking exception.

[GPL linking exception]: https://en.wikipedia.org/wiki/GPL_linking_exception
[diStorm3]: https://github.com/gdabah/distorm/
