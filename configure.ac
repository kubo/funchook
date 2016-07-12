AC_INIT([duckhook], [0.1])

AC_PROG_CC
AC_GNU_SOURCE
AC_CANONICAL_HOST

if test "$GCC"; then
   CFLAGS="$CFLAGS -Wall"
fi

case "$host_os" in
mingw32)
  DUCKHOOK_OS=windows
  LIBDUCKHOOK_SO=duckhook.dll
  CFLAGS="$CFLAGS -DBUILD_DUCKHOOK_DLL"
  LINK_SHARED="\$(CC) -shared -Wl,--out-implib,duckhook.lib"
  COPY_DLL_ON_TEST=
  ;;
linux-gnu)
  DUCKHOOK_OS=linux
  LIBDUCKHOOK_SO=libduckhook.so
  CFLAGS="$CFLAGS -fPIC"
  LINK_SHARED="\$(CC) -shared -Wl,--version-script,\$(srcdir)/duckhook.map"
  COPY_DLL_ON_TEST='#'
  LIBS="-ldl"
  ;;
*)
  AC_MSG_ERROR([Unsupported OS: $host_os])
  exit 1
esac
AC_SUBST(DUCKHOOK_OS)
AC_SUBST(LIBDUCKHOOK_SO)
AC_SUBST(LINK_SHARED)
AC_SUBST(COPY_DLL_ON_TEST)

AC_CHECK_SIZEOF(void*)

if test "$ac_cv_sizeof_voidp" = 4; then
  DUCKHOOK_CPU=x86
else
  DUCKHOOK_CPU=x86_64
fi
AC_SUBST(DUCKHOOK_CPU)

AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_OUTPUT
