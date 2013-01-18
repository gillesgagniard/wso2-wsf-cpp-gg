prglibdir=$(prefix)/modules/sandesha2
prglib_LTLIBRARIES = libsandesha2.la

libsandesha2_la_SOURCES = sandesha2_msg_ctx.c\
                          mod_sandesha2.c\
                          msg_validator.c 

INCLUDES = -I$(top_builddir)/include \
            @AXIS2INC@ \
		   	@AXIOMINC@ \
		   	@NEETHIINC@ \
		   	@UTILINC@
libsandesha2_la_LIBADD = ../handlers/libsandesha_handlers.la\
                        ../msgprocessors/libsandesha2_msgprocessors.la\
                        ../storage/beans/libsandesha2_storage_beans.la\
						../storage/common/libsandesha2_storage.la\
                        ../storage/sqlite/libsandesha2_permanent.la\
                        ../transport/libsandesha2_transport.la\
                        ../util/libsandesha_util.la\
                        ../wsrm/libsandesha2_wsrm.la \
                        ../polling/libsandesha2_polling.la 

install-data-hook:
	cp -f $(prefix)/modules/sandesha2/libsandesha2* $(prefix)/lib/

