prglibdir=$(prefix)/samples/lib/rampartc
prglib_LTLIBRARIES = librdflatfile.la
librdflatfile_la_SOURCES = rampart_replay_detector_flat_file.c
librdflatfile_la_LIBADD  = $(LDFLAGS) \
						   		-L$(AXIS2C_HOME)/lib \
								-laxutil \
								../../src/util/librampart.la

INCLUDES = -I ../../include\
			@AXIS2INC@
