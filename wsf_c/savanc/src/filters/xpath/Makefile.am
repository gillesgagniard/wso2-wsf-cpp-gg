datadir=$(prefix)/modules/savan
lib_LTLIBRARIES = libsavan_filter_mod.la

libsavan_filter_mod_la_SOURCES = filter_mod.c
libsavan_filter_mod_la_LIBADD = ../common/libsavan_common_filter_mod.la -lxml2

data_DATA=template.xsl

INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/savan \
			-I. \
			@AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
			@XPATHINC@ \
		   	@UTILINC@

EXTRA_DIST=template.xsl
