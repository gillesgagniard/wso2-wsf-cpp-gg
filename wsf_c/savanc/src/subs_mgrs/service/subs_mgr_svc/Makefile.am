prglibdir=$(prefix)/services/subscription
prglib_LTLIBRARIES = libsubscription.la
prglib_DATA= services.xml
noinst_HEADERS = savan_subs_mgr_svc.h
SUBDIRS =
libsubscription_la_SOURCES = subs_mgr.c subs_mgr_skel.c
libsubscription_la_LIBADD  = ../../../client/libsavan_client.la

INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/savan \
			-I. \
			@AXIOMINC@ \
			@UTILINC@ \
			@NEETHIINC@ \
			@AXIS2INC@ 

EXTRA_DIST=services.xml savan_subs_mgr_svc.h
