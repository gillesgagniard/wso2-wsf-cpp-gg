SUBDIRS = src 
docsdir=$(prefix)/docs
includedir=$(prefix)/include/rampart-1.3.0
include_HEADERS=$(top_builddir)/include/*.h
# xdocs contains whole directories, cannot install them this way ... install doesn't support that !
#docs_DATA=xdocs/*
EXTRA_DIST = LICENSE NOTICE build.sh autogen.sh samples build test #xdocs

check:	
	./rampart-tests.sh

dist-hook:
	    cp -r target/docs $(distdir) 
		cp -r xdocs/api $(distdir)/docs


