Duckhook - an API hook library
==============================

This library depends on [diStorm3][].

TODO
----

* write more documents.
* add a function to get the error reason when `duckhook_install` returns NULL.
* add a function to debug duckhook itself.
* add tests.

Supportd Platform
-----------------

* Linux x86_64
* Linux 32-bit
* Windows x64 (*1)
* Windows 32-bit (*1)

*1 compiled by mingw-w64 and tested on Wine. I havn't tested it on Windows yet.

Compilation
-----------

```shell
$ git clone https://github.com/kubo/duckhook.git # diStorm3 is also cloned as a submodule.
$ cd src
$ make
```

Example
-------

```c
static ssize_t (*recv_orig)(int sockfd, void *buf, size_t len, int flags);

static ssize_t recv_hook(int sockfd, void *buf, size_t len, int flags);
{
    ssize_t rv;

    ... do your task: logging, etc. ...
    rv = recv_orig(sockfd, buf, len, flags); /* call the original recv(). */
    ... do your task: logging, checking received data, etc. ...
    return rv;
}

int instal_hook()
{
    /* Change the first 5 bytes of the recv function to redirect
     * all recv calls to recv_hook.
     * The return value is used to call the original recv function
     * in recv_hook.
     */
    recv_orig = duckhook_install(recv, recv_hook, NULL);

    if (recv_orig == NULL) {
       return -1;
    }
    ... other stuff ...
}

```

```
    duckhook_memo_t *memo;

    /* install a hook. The modified part of the recv function
     * is saved to 'memo'.
     */
    recv_orig = duckhook_install(recv, recv_hook, &memo);

    ...

    /* restore the recv function. */
    duckhook_uninstall(memo);

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
