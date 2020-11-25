AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-route_monitoring.la
else
plugin_LTLIBRARIES = libstrongswan-route_monitoring.la
endif

libstrongswan_route_monitoring_la_SOURCES = \
	route_monitoring.c route_monitoring.h  \
	route_monitoring_plugin.c route_monitoring_plugin.h


libstrongswan_route_monitoring_la_LDFLAGS = -module -avoid-version
libstrongswan_route_monitoring_la_LIBADD = -liphlpapi
