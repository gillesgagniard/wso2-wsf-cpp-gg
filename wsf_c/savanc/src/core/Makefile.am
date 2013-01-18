prglibdir=$(prefix)/modules/savan
prglib_LTLIBRARIES = libmod_savan.la
prglib_DATA= ../data/module.xml

libmod_savan_la_SOURCES = mod_savan.c savan_sub_processor.c

INCLUDES = -I$(top_builddir)/include \
		@AXIOMINC@ \
		@UTILINC@ \
		@AXIS2INC@ \
		@NEETHIINC@

libmod_savan_la_LIBADD = \
                        ../handlers/libsavan_handlers.la\
						../util/libsavan_util.la \
						../subs_mgrs/@SAVAN_SUBS_MGR@/libsavan_subs_mgr.la
