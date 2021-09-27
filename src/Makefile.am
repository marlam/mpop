bin_PROGRAMS = mpop

mpop_SOURCES = \
	conf.c conf.h \
	delivery.c delivery.h \
	list.c list.h \
	mpop.c \
	net.c net.h \
	netrc.c netrc.h \
	pop3.c pop3.h \
	readbuf.c readbuf.h \
	stream.c stream.h \
	tools.c tools.h \
	uidls.c uidls.h \
	xalloc.c xalloc.h \
	gettext.h \
	base64.c base64.h \
	md5.c md5.h \
	md5-apps.c md5-apps.h \
	password.c password.h

if HAVE_TLS
mpop_SOURCES += mtls.c mtls.h
endif
if HAVE_GNUTLS
mpop_SOURCES += mtls-gnutls.c
endif
if HAVE_OPENSSL
mpop_SOURCES += mtls-openssl.c
endif
if HAVE_LIBTLS
mpop_SOURCES += mtls-libtls.c
endif

AM_CPPFLAGS = $(tls_CFLAGS) $(libgsasl_CFLAGS) $(libidn2_CFLAGS) $(libsecret_CFLAGS)

mpop_LDADD =  $(tls_LIBS) $(libgsasl_LIBS) $(libidn2_LIBS) $(libsecret_LIBS) $(LIBINTL)

DEFS += -DLOCALEDIR=\"$(localedir)\"

if BUILD_MPOPD
bin_PROGRAMS += mpopd
mpopd_SOURCES = mpopd.c base64.c base64.h password.c password.h tools.c tools.h xalloc.c xalloc.h netrc.c netrc.h
mpopd_LDADD =  $(libsecret_LIBS)
endif
