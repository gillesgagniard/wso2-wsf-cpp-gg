prgbindir=$(prefix)/samples/bin/sandesha2
prgbin_PROGRAMS = rm_echo_1_0
rm_echo_1_0_SOURCES = rm_echo.c echo_util.c

rm_echo_1_0_LDADD   =  \
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

INCLUDES =	-I../../include \
		-I../../include/sandesha2 \
		@AXIS2INC@

EXTRA_DIST=echo_util.h
