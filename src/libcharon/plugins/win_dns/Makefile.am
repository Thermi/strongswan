AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-win-dns.la
else
plugin_LTLIBRARIES = libstrongswan-win-dns.la
endif

libstrongswan_win_dns_la_SOURCES = \
	win_dns_plugin.h win_dns_plugin.c \
	win_dns_handler.h win_dns_handler.c

libstrongswan_win_dns_la_LIBADD = -liphlpapi
libstrongswan_win_dns_la_LDFLAGS = -module -avoid-version
