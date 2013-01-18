prglibdir=$(prefix)/services/sec_echo
#samplesdir=$(prefix)/samples/src/server/sec_echo
prglib_LTLIBRARIES = libsec_echo.la
#samples_DATA=echo.c echo_skeleton.c echo.h services.xml Makefile.am Makefile.in
prglib_DATA= services.xml
EXTRA_DIST = services.xml echo.h
noinst_HEADERS = echo.h
SUBDIRS =
libsec_echo_la_SOURCES = echo.c echo_skeleton.c
libsec_echo_la_LIBADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
					-L$(prefix)/lib \
					-lrampart


INCLUDES = @AXIS2INC@ \
	-I$(AXIS2C_HOME)/include \
	            -I ../../../include

