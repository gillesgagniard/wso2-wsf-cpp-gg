prglibdir=$(prefix)/samples/lib/rampartc
prglib_LTLIBRARIES = libsctprovider.la libsctprovider_hashdb.la
libsctprovider_la_SOURCES = sct_provider_stored_key.c
libsctprovider_la_LIBADD  = $(LDFLAGS) \
						   		-L$(AXIS2C_HOME)/lib \
								-laxutil \
								../../src/util/librampart.la

libsctprovider_hashdb_la_SOURCES = sct_provider_hash_map.c
libsctprovider_hashdb_la_LIBADD  = $(LDFLAGS) \
						   		-L$(AXIS2C_HOME)/lib \
								-laxutil \
								../../src/util/librampart.la
								 
INCLUDES = -I ../../include\
			@AXIS2INC@
