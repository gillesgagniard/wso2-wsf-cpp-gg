prgbindir=$(prefix)/bin/samples/rampart/omxmlsec/xmlenc
prgbin_PROGRAMS = enc

enc_SOURCES =  enc.c

INCLUDES = @AXIS2INC@ \
            -I ../../../include 

enc_LDADD   = -laxutil \
                    -laxis2_axiom \
                    -lxml2 \
					../../src/core/libmod_rampart.la


EXTRA_DIST = input.xml		   
