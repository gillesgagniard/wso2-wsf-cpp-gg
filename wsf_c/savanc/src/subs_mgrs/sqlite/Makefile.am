lib_LTLIBRARIES = libsavan_subs_mgr.la

libsavan_subs_mgr_la_SOURCES = subs_mgr.c sqlite3.c

libsavan_subs_mgr_la_LIBADD = ../common/libsavan_common_subs_mgr.la

INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/savan \
			-I. \
			@AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
		   	@UTILINC@

EXTRA_DIST=
