AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-gmpdh.la
else
plugin_LTLIBRARIES = libstrongswan-gmpdh.la
endif

libstrongswan_gmpdh_la_SOURCES = \
	gmpdh_plugin.h gmpdh_plugin.c \
	../gmp/gmp_diffie_hellman.c ../gmp/gmp_diffie_hellman.h


libstrongswan_gmpdh_la_LDFLAGS = -module -avoid-version -Wl,-Bstatic -Wl,-lgmp -Wl,-Bdynamic -Wl,--as-needed $(FPIC)
libstrongswan_gmpdh_la_LIBADD  =
