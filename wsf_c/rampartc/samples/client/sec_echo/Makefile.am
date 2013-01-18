prgbindir=$(prefix)/samples/bin/rampartc
prgbin_PROGRAMS = sec_echo
datadir=$(prefix)/samples/bin/rampartc
data_DATA= update_n_run.sh
sec_echo_SOURCES = echo.c 

sec_echo_LDADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
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
