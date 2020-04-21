AC_INIT([pwdstorage-bcrypt-plugin],[0.1])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_SRCDIR([.])

AC_CANONICAL_HOST
AC_PROG_CC

AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for
--enable-debug]) ;;
esac],
[debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")


case $host in
  *-*-linux*)
    AC_DEFINE([LINUX], [1], [Linux])
    AC_DEFINE([_GNU_SOURCE], [1], [GNU Source])
    platform="linux"
    initdir='$(sysconfdir)/rc.d/init.d'
    # do arch specific linux stuff here
    case $host in
      i*86-*-linux*)
        AC_DEFINE([CPU_x86], [], [cpu type x86])
        ;;
      x86_64-*-linux*)
        AC_DEFINE([CPU_x86_64], [1], [cpu type x86_64])

        # This turns on and off LFDS inside of libsds
        # wibrown -- 2017-02-21 disabled temporarily
        # with_atomic_queue="yes"
        # AC_DEFINE([ATOMIC_QUEUE_OPERATIONS], [1], [enabling atomic queue operations])
        ;;
      aarch64-*-linux*)
        AC_DEFINE([CPU_arm], [], [cpu type arm])
        ;;
      arm-*-linux*)
        AC_DEFINE([CPU_arm], [], [cpu type arm])
        ;;
      ppc64le-*-linux*)
        ;;
      ppc64-*-linux*)
        ;;
      ppc-*-linux*)
        ;;
      s390-*-linux*)
        ;;
      s390x-*-linux*)
        ;;
    esac
    # some programs use the native thread library directly
    THREADLIB=-lpthread
    AC_SUBST([THREADLIB], [$THREADLIB])
    LIBCRYPT=-lcrypt
    AC_SUBST([LIBCRYPT], [$LIBCRYPT])
    AC_DEFINE([USE_POSIX_RWLOCKS], [1], [POSIX rwlocks])
    ;;
  *-*-freebsd*)
    AC_DEFINE([FREEBSD], [1], [FreeBSD])
    platform="freebsd"
    initdir='$(sysconfdir)/rc.d'
    THREADLIB=-lthr
    AC_SUBST([THREADLIB], [$THREADLIB])
    AC_DEFINE([USE_POSIX_RWLOCKS], [1], [POSIX rwlocks])
    LIBDL=
    ;;
  ia64-hp-hpux*)
    AC_DEFINE([hpux], [1], [HP-UX])
    AC_DEFINE([HPUX], [1], [HP-UX])
    AC_DEFINE([HPUX11], [1], [HP-UX 11])
    AC_DEFINE([HPUX11_23], [1], [HP-UX 11.23])
    AC_DEFINE([CPU_ia64], [], [cpu type ia64])
    AC_DEFINE([OS_hpux], [1], [OS HP-UX])
    AC_DEFINE([_POSIX_C_SOURCE], [199506L], [POSIX revision])
    AC_DEFINE([_HPUX_SOURCE], [1], [Source namespace])
    AC_DEFINE([_INCLUDE_STDC__SOURCE_199901], [1], [to pick up all of the printf format macros in inttypes.h])
    # assume 64 bit
    perlexec='/opt/perl_64/bin/perl'
    platform="hpux"
    initconfigdir="/$PACKAGE_NAME/config"
    # HPUX doesn't use /etc for this
    initdir=/init.d
    ;;
  hppa*-hp-hpux*)
    AC_DEFINE([hpux], [1], [HP-UX])
    AC_DEFINE([HPUX], [1], [HP-UX])
    AC_DEFINE([HPUX11], [1], [HP-UX 11])
    AC_DEFINE([HPUX11_11], [1], [HP-UX 11.11])
    AC_DEFINE([CPU_hppa], [], [cpu type pa-risc])
    AC_DEFINE([OS_hpux], [1], [OS HP-UX])
    AC_DEFINE([_POSIX_C_SOURCE], [199506L], [POSIX revision])
    AC_DEFINE([_HPUX_SOURCE], [1], [Source namespace])
    AC_DEFINE([_INCLUDE_STDC__SOURCE_199901], [1], [to pick up all of the printf format macros in inttypes.h])
    # assume 64 bit
    initconfigdir="/$PACKAGE_NAME/config"
    perlexec='/opt/perl_64/bin/perl'
    platform="hpux"
    # HPUX doesn't use /etc for this
    initdir=/init.d
    ;;
  *-*-solaris*)
    AC_DEFINE([SVR4], [1], [SVR4])
    AC_DEFINE([__svr4], [1], [SVR4])
    AC_DEFINE([__svr4__], [1], [SVR4])
    AC_DEFINE([_SVID_GETTOD], [1], [SVID_GETTOD])
    AC_DEFINE([SOLARIS], [1], [SOLARIS])
    AC_DEFINE([OS_solaris], [1], [OS SOLARIS])
    AC_DEFINE([sunos5], [1], [SunOS5])
    AC_DEFINE([OSVERSION], [509], [OS version])
    AC_DEFINE([_REENTRANT], [1], [_REENTRANT])
    AC_DEFINE([NO_DOMAINNAME], [1], [no getdomainname])
dnl socket nsl and dl are required to link several programs and libdb
    LIBSOCKET=-lsocket
    AC_SUBST([LIBSOCKET], [$LIBSOCKET])
    LIBNSL=-lnsl
    AC_SUBST([LIBNSL], [$LIBNSL])
    LIBDL=-ldl
    AC_SUBST([LIBDL], [$LIBDL])
dnl Cstd and Crun are required to link any C++ related code
    LIBCSTD=-lCstd
    AC_SUBST([LIBCSTD], [$LIBCSTD])
    LIBCRUN=-lCrun
    AC_SUBST([LIBCRUN], [$LIBCRUN])
    platform="solaris"
    initdir='$(sysconfdir)/init.d'
    case $host in
      i?86-*-solaris2.1[[0-9]]*)
        dnl I dont know why i386 need this explicit
        AC_DEFINE([HAVE_GETPEERUCRED], [1], [have getpeerucred])
        ;;
      sparc-*-solaris*)
        dnl includes some assembler stuff in counter.o
        AC_DEFINE([CPU_sparc], [], [cpu type sparc])
        TARGET='SPARC'
        ;;
    esac
    ;;
  *)
    platform=""
    ;;
esac

# Determine PIC flag, adjust default CFLAGS
pic_flag=
shared_flag=
AC_MSG_CHECKING(Determining PIC compiler/shared linker flag)
if test "$GCC" = yes; then
  AC_MSG_RESULT(-fPIC)
  pic_flag=-fPIC
  shared_flag=-shared
else
  case "$host" in
    *-*-hpux*)
      AC_MSG_RESULT("+Z")
      pic_flag="+Z"
      ;;
    *-*-solaris*)
      AC_MSG_RESULT(-Kpic)
      pic_flag=-Kpic
      shared_flag=-G
      ;;
    *-*-linux*)
      AC_MSG_RESULT(-fPIC)
      pic_flag=-fPIC
      # Any Linux compiler had better be gcc compatible.
      ;;
    *)
      echo "Host : $host"
      AC_MSG_RESULT("<none>")
      ;;
  esac
fi
AC_SUBST(pic_flag)
AC_SUBST(shared_flag)

# check for --with-nss
AC_MSG_CHECKING(for --with-nss)
AC_ARG_WITH(nss, AS_HELP_STRING([--with-nss=PATH],[NSS include directory]),
[
  if test -e "$withval"/ssl.h
  then
    AC_MSG_RESULT([using $withval])
    nss_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[
  AC_MSG_RESULT(no)
  nss_inc=""
])
AC_SUBST([nss_inc])

# check for --with-nspr
AC_MSG_CHECKING(for --with-nspr)
AC_ARG_WITH(nspr, AS_HELP_STRING([--with-nspr=PATH],[Mozilla Portable Runtime include directory]),
[
  if test -e "$withval"/prtypes.h
  then
    AC_MSG_RESULT([using $withval])
    nspr_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[
  AC_MSG_RESULT(no)
  nspr_inc=""
])
AC_SUBST([nspr_inc])


# check for --with-ds
AC_MSG_CHECKING(for --with-ds)
AC_ARG_WITH(ds, AS_HELP_STRING([--with-ds=PATH],[389 DS sources directory]),
[
  if test -e $withval/ldap/servers/slapd/slapi-plugin.h
  then
    AC_MSG_RESULT([using $withval])
    ds_inc="-I$withval/include -I$withval/include/base -I$withval/ldap/include -I$withval/ldap/servers/slapd"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[
  AC_MSG_RESULT(no)
  ds_inc=""
])
AC_SUBST([ds_inc])

# $passwdqc_inc
CPPFLAGS="$ds_inc $nspr_inc $nss_inc"
#echo $CPPFLAGS
CFLAGS=""
AC_CHECK_HEADERS(ldap.h,[], [AC_MSG_ERROR([unable to find the ldap.h include])])
#AC_CHECK_HEADERS(slapi-plugin.h,[], [AC_MSG_ERROR([unable to find the slapi-plugin.h include])])
#AC_CHECK_HEADERS(crypt_blowfish.h,[], [AC_MSG_ERROR([unable to find the crypt_blowfish.h include])])


AC_OUTPUT([
Makefile
])