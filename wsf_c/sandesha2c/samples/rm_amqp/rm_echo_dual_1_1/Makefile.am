prgbindir = $(prefix)/samples/bin/sandesha2/amqp

prgbin_PROGRAMS = rm_echo_dual_1_1

rm_echo_dual_1_1_SOURCES = rm_echo_1_1.c echo_util.c

rm_echo_dual_1_1_LDADD = ../../../src/core/libsandesha2.la \
						 -laxutil \
                    	 -laxis2_axiom \
                    	 -laxis2_engine \
                    	 -laxis2_parser \
                    	 -lpthread \
                    	 ../../../src/client/libsandesha2_client.la \
                    	 $(GUTHTHILA_LIBS) \
                    	 $(LIBXML2_LIBS)

INCLUDES = -I../../../include \
		   @AXIS2INC@

EXTRA_DIST=echo_util.h
