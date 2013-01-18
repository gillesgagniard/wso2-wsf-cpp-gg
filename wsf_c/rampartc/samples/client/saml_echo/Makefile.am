prgbindir=$(prefix)/samples/bin/rampartc
prgbin_PROGRAMS = saml_echo 
saml_echo_SOURCES = echo.c 

saml_echo_LDADD   = $(LDFLAGS) \
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

EXTRA_DIST = update_n_run.sh update_n_run.bat

install-data-hook:
		cp update_n_run.sh $(prefix)/samples/bin/rampartc/saml_echo_update_n_run.sh
