lib_LTLIBRARIES = libsavan_publisher.la
libsavan_publisher_la_SOURCES = publisher.c
data_DATA=
libsavan_publisher_la_LIBADD = $(top_builddir)/src/util/libsavan_util.la \
							../../filters/@SAVAN_FILTER_LIB@ \
							../common/libsavan_common_publisher.la \
							../../util/libsavan_util.la \
							../../subs_mgrs/@SAVAN_SUBS_MGR@/libsavan_subs_mgr.la

INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/savan \
			-I. \
			@AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
			@XPATHINC@ \
		   	@UTILINC@

EXTRA_DIST=
