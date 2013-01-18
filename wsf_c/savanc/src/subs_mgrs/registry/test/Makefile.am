TESTS = test_registry
check_PROGRAMS = test_registry
noinst_PROGRAMS = test_registry
SUBDIRS =
test_registry_SOURCES = test_registry.c xml.c main.c


test_registry_LDADD   =	../libsavan_storage.la \
				$(LDFLAGS) \
				-L$(LIBCURL_LIBS) \
                -L$(AXIS2C_HOME)/lib \
                -laxutil \
                -laxis2_axiom \
				-lregistry_client \
				-lcurl \
                $(GUTHTHILA_LIBS)


INCLUDES = -I$(top_builddir)/include \
			-I$(top_builddir)/include/savan \
			-I. \
			@AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
			@REGISTRYINC@ \
		   	@UTILINC@
