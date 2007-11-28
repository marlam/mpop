bin_PROGRAMS = mpop

mpop_SOURCES = \
	conf.c conf.h \
	delivery.c delivery.h \
	list.c list.h \
	mpop.c \
	net.c net.h \
	netrc.c netrc.h \
	pop3.c pop3.h \
	stream.c stream.h \
	tools.c tools.h \
	uidls.c uidls.h

mpop_LDADD = @tls_obj@ $(top_builddir)/gnulib/libgnu.a $(LIBINTL)

mpop_DEPENDENCIES = @tls_obj@

EXTRA_mpop_SOURCES = tls.c tls.h

AM_CPPFLAGS = -I$(top_srcdir)/gnulib

localedir = $(datadir)/locale
DEFS += -DLOCALEDIR=\"$(localedir)\"
