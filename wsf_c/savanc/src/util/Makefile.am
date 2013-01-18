datadir=$(prefix)/modules/savan
lib_LTLIBRARIES = libsavan_util.la

libsavan_util_la_SOURCES = savan_util.c error.c

libsavan_util_la_LIBADD = ../subscribers/libsavan_subscribers.la

INCLUDES = -I$(top_builddir)/include \
		@AXIOMINC@ \
		@AXIS2INC@ \
		@UTILINC@ \
		@NEETHIINC@

