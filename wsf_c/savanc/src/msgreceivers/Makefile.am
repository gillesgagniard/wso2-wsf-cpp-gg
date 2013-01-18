lib_LTLIBRARIES = libsavan_msgreceivers.la

libsavan_msgreceivers_la_SOURCES = savan_msg_recv.c

libsavan_msgreceivers_la_LIBADD = ../publishers/@SAVAN_PUBLISHER_LIB@ \
								  	../subs_mgrs/@SAVAN_SUBS_MGR@/libsavan_subs_mgr.la \
									../util/libsavan_util.la


INCLUDES = -I$(top_builddir)/include \
		@AXIS2INC@ \
		@AXIOMINC@ \
		@UTILINC@ 
