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
	md5.c md5.h \
	md5-apps.c md5-apps.h

if HAVE_TLS
mpop_SOURCES += tls.c tls.h
endif

if HAVE_LIBGSASL
else
mpop_SOURCES += base64.c base64.h
endif

AM_CPPFLAGS = $(tls_CFLAGS) $(libgsasl_CFLAGS) $(libidn_CFLAGS) $(libsecret_CFLAGS)

mpop_LDADD =  $(tls_LIBS) $(libgsasl_LIBS) $(libidn_LIBS) $(libsecret_LIBS) $(LIBINTL)

DEFS += -DLOCALEDIR=\"$(localedir)\"
