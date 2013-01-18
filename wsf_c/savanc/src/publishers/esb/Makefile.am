lib_LTLIBRARIES = libsavan_publisher.la

libsavan_publisher_la_SOURCES = publisher.c
libsavan_publisher_la_LIBADD = $(top_builddir)/src/util/libsavan_util.la \
							../../filters/@SAVAN_FILTER_LIB@ \
							../common/libsavan_common_publisher.la

data_DATA=

INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/savan \
			-I. \
			@AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
			@XPATHINC@ \
			@ESBPUBINC@ \
		   	@UTILINC@

EXTRA_DIST=
