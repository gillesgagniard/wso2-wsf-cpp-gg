prgbindir=$(prefix)/samples/bin/rampartc
prgbin_PROGRAMS = sts_client 
datadir=$(prefix)/samples/bin/rampartc
#data_DATA= client.xml service.xml
sts_client_SOURCES = client.c 

sts_client_LDADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
					-L$(prefix)/lib \
		    	-lrampart \
					-laxutil \
                    -laxis2_axiom \
					-lneethi \
                    -laxis2_engine \
                    -laxis2_parser \
                    -lpthread \
                    -laxis2_http_sender \
                    -laxis2_http_receiver \
                    $(GUTHTHILA_LIBS) \
                    $(LIBXML2_LIBS)

INCLUDES = @AXIS2INC@ \
		   -I$(AXIS2C_HOME)/include \
            -I ../../../include 

#EXTRA_DIST = client.xml service.xml
