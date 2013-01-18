prglibdir=$(prefix)/services/saml_sts
#samplesdir=$(prefix)/samples/src/server/saml_sts
prglib_LTLIBRARIES = libsaml_sts.la
#samples_DATA=issuer.c saml_skeleton.c saml_issuer.h services.xml Makefile.am 
prglib_DATA= services.xml
EXTRA_DIST = services.xml saml_issuer.h 
noinst_HEADERS = saml_issuer.h 
SUBDIRS =
libsaml_sts_la_SOURCES = issuer.c saml_skeleton.c
libsaml_sts_la_LIBADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
					-L$(prefix)/lib \
					-lrampart


INCLUDES = @AXIS2INC@ \
	-I$(AXIS2C_HOME)/include \
	            -I ../../../include
