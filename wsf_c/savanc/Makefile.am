datadir=$(prefix)
SUBDIRS = src
docsdir=$(prefix)/docs
samplesdir=$(prefix)/samples/savanc
includedir=$(prefix)/include/savan-1.0
sysconfdir=$(prefix)
include_HEADERS=$(top_builddir)/include/*.h

sysconf_DATA=src/data/axis2.xml

dist-hook:
	cp -rf xdocs/docs $(distdir)/
	cp -rf xdocs/api $(distdir)/docs/
	sh dist_hook.sh
EXTRA_DIST = build.sh autogen.sh build samples LICENSE


