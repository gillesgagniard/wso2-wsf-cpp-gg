prgbindir=$(prefix)/samples/bin/sandesha2
prgbin_PROGRAMS = rm_ping_1_1
rm_ping_1_1_SOURCES = rm_ping_1_1.c

rm_ping_1_1_LDADD   =  \
			../../src/core/libsandesha2.la \
					-laxutil \
                    -laxis2_axiom \
                    -laxis2_engine \
                    -laxis2_parser \
                    -lpthread \
                    -laxis2_http_sender \
                    -laxis2_http_receiver \
                    ../../src/client/libsandesha2_client.la \
                    $(GUTHTHILA_LIBS) \
                    $(LIBXML2_LIBS)

INCLUDES = @AXIS2INC@ \
			-I../../include 
