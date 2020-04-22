PICFLAG = @pic_flag@
SHARED = @shared_flag@
DS_INCLUDES=@ds_inc@
NSPR_INCLUDES=@nspr_inc@
#PASSWDQC_INCLUDES=@passwdqc_inc@

ACLOCAL_AMFLAGS=-I m4

pkglibdir=$(libdir)/dirsrv/plugins
pkgdatadir=$(datadir)/dirsrv/data/plugins

LIBNAME = libpwdstorage-bcrypt-plugin.so
CONFFILE = bcrypt-conf.ldif
# $(PASSWDQC_INCLUDES)
if DEBUG
AM_CFLAGS = $(PICFLAG) -O0 -g3 -m64 -c -std=gnu99 \
    $(DS_INCLUDES) $(NSPR_INCLUDES) -D SLAPD_BCRYPT_DEBUG
else
AM_CFLAGS = $(PICFLAG) -O2 -m64 -c -std=gnu99 \
    $(DS_INCLUDES) $(NSPR_INCLUDES)
endif



pkglib_LTLIBRARIES = libpwdstorage-bcrypt-plugin.la
libpwdstorage_bcrypt_plugin_la_SOURCES = crypt_blowfish.c pw-bcrypt.c
libpwdstorage_bcrypt_plugin_la_LDFLAGS = -avoid-version

pkgdata_DATA = $(srcdir)/$(CONFFILE)

distclean: clean
	rm -f config.* *~ Makefile Makefile.in autoscan.log
	rm -rf autom4te.cache

check-syntax:
	gcc -Wall -fsyntax-only -Wno-variadic-macros -std=c99 $(INCLUDES) $(DS_INCLUDES) $(NSPR_INCLUDES) $(CHK_SOURCES)