AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon -DWIN32

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) -DWIN32

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-block-dns.la
else
plugin_LTLIBRARIES = libstrongswan-block-dns.la
endif

libstrongswan_block_dns_la_SOURCES = \
	block_dns_plugin.h block_dns_plugin.c \
	block_dns_filter.h block_dns_filter.c \
	block_dns_listener.h block_dns_listener.c

libstrongswan_block_dns_la_LIBADD = -liphlpapi -lfwpuclnt
libstrongswan_block_dns_la_LDFLAGS = -module -avoid-version
