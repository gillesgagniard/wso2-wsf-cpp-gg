datadir=$(prefix)/modules/sandesha2
includedir=$(prefix)/include/sandesha2-0.92
docsdir=$(prefix)/docs/sandesha2c
sysconfdir=$(prefix)

SUBDIRS = src
include_HEADERS= include/*.h

data_DATA = LICENSE config/module.xml

docs_DATA=

sysconf_DATA=config/axis2.xml

install-data-hook: 
	cp -rf xdocs/docs/* $(docsdir)


EXTRA_DIST=LICENSE config xdocs build samples ides


dist-hook:
	rm -rf `find $(distdir)/ -type d -name .svn`
	rm -rf `find $(distdir)/ -type f -name *.la`
	rm -rf `find $(distdir)/ -type f -name *.o`
	rm -rf `find $(distdir)/ -type f -name *.lo`
	rm -rf `find $(distdir)/ -type f -name *.loT`
	rm -rf `find $(distdir)/ -type d -name .deps`
	rm -rf `find $(distdir)/ -type d -name .libs`
	rm -rf `find $(distdir)/ -type f -name Makefile`
	rm -rf `find $(distdir)/ -type f -name sandesha2c-sample-src-${PACKAGE_VERSION}.tar.gz`
	rm -rf `find $(distdir)/ -type d -name autom4te.cache`
	sh dist.sh

bindist: $(bin_PROGRAMS)
	rm -rf sandesha2c-bin-${PACKAGE_VERSION}-linux
	sh bindist.sh
	mkdir sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp -r `pwd`/deploy/* sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp AUTHORS sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp COPYING sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp CREDITS sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp INSTALL sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp LICENSE sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp NEWS sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp NOTICE sandesha2c-bin-${PACKAGE_VERSION}-linux
	cp README sandesha2c-bin-${PACKAGE_VERSION}-linux
	tar -cf - sandesha2c-bin-${PACKAGE_VERSION}-linux | gzip -c > sandesha2c-bin-${PACKAGE_VERSION}-linux.tar.gz
	rm -rf sandesha2c-bin-${PACKAGE_VERSION}-linux
