AC_INIT([funchook], [0.1])

AC_PROG_CC
AC_GNU_SOURCE
AC_CANONICAL_HOST

if test "$GCC"; then
   CFLAGS="$CFLAGS -Wall -fvisibility=hidden"
fi

AC_CHECK_SIZEOF(void*)
if test "$ac_cv_sizeof_voidp" = 4; then
  FUNCHOOK_CPU=x86
else
  FUNCHOOK_CPU=x86_64
fi
AC_SUBST(FUNCHOOK_CPU)

IF_WIN32='#'
IF_LINUX='#'
IF_OSX='#'

if test "$EXEEXT"; then
  FUNCHOOK_OS=windows
  LIBFUNCHOOK_SO=funchook.dll
  CFLAGS="$CFLAGS -DFUNCHOOK_EXPORTS"
  LINK_SHARED="\$(CC) -shared -Wl,--out-implib,funchook.lib"
  IF_WIN32=
else
  FUNCHOOK_OS=unix
  PIC_CFLAGS="-fPIC"
  LINK_SHARED="\$(CC) -shared"
  case "$host_os" in
  linux*)
    LIBFUNCHOOK_SO=libfunchook.so
    LIBS="-ldl"
    IF_LINUX=
    ;;
  darwin*)
    LIBFUNCHOOK_SO=libfunchook.dylib
    IF_OSX=
    ;;
  esac
fi

AC_CHECK_DECLS([_sys_nerr, _sys_errlist, sys_nerr, sys_errlist])

AC_SUBST(FUNCHOOK_OS)
AC_SUBST(LIBFUNCHOOK_SO)
AC_SUBST(LINK_SHARED)
AC_SUBST(PIC_CFLAGS)
AC_SUBST(IF_WIN32)
AC_SUBST(IF_LINUX)
AC_SUBST(IF_OSX)

AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_OUTPUT
