noinst_LTLIBRARIES = libsandesha2_permanent.la

libsandesha2_permanent_la_SOURCES = \
								permanent_create_seq_mgr.c \
								permanent_invoker_mgr.c \
								permanent_sender_mgr.c \
								permanent_next_msg_mgr.c \
								permanent_seq_property_mgr.c \
								permanent_storage_mgr.c \
								permanent_bean_mgr.c \
								msg_store_bean.c \
								sqlite3.c

INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/sandesha2 \
			-I. \
			@AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
		   	@UTILINC@

EXTRA_DIST=sandesha2_permanent_bean_mgr.h \
		sandesha2_sqls.h \
		sqlite3.h

