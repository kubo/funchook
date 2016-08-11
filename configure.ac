AC_INIT([duckhook], [0.1])

AC_PROG_CC
AC_GNU_SOURCE
AC_CANONICAL_HOST

if test "$GCC"; then
   CFLAGS="$CFLAGS -Wall -fvisibility=hidden"
fi

AC_CHECK_SIZEOF(void*)
if test "$ac_cv_sizeof_voidp" = 4; then
  DUCKHOOK_CPU=x86
else
  DUCKHOOK_CPU=x86_64
fi
AC_SUBST(DUCKHOOK_CPU)

if test "$EXEEXT"; then
  DUCKHOOK_OS=windows
  LIBDUCKHOOK_SO=duckhook.dll
  CFLAGS="$CFLAGS -DBUILD_DUCKHOOK_DLL"
  LINK_SHARED="\$(CC) -shared -Wl,--out-implib,duckhook.lib"
  IF_WIN32=
else
  DUCKHOOK_OS=unix
  PIC_CFLAGS="-fPIC"
  LINK_SHARED="\$(CC) -shared"
  IF_WIN32='#'
  case "$host_os" in
  linux*)
    LIBDUCKHOOK_SO=libduckhook.so
    LIBS="-ldl"
    ;;
  darwin*)
    LIBDUCKHOOK_SO=libduckhook.dylib
    LIBS="-install_name @rpath/libduckhook.dylib"
    ;;
  esac
fi

AC_SUBST(DUCKHOOK_OS)
AC_SUBST(LIBDUCKHOOK_SO)
AC_SUBST(LINK_SHARED)
AC_SUBST(PIC_CFLAGS)
AC_SUBST(IF_WIN32)

AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_OUTPUT
