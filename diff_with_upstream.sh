#!/bin/sh
#diff -u -r -x "*.Plo" -x "*.la" -x "Makefile*" -x "*.lai" -x "*.o" -x "*.so" -x "*m4*" -x configure ../wsfcpp-trunk.origin/wsf_c/ ./wsf_c/ 2>/dev/null
diff -u -r -x "*.Plo" -x "*.la" -x "Makefile*" -x "*.lai" -x "*.o" -x "*.so" -x "*m4*" -x "*.lo" -x .deps -x .libs -x config.log -x config.h -x config.status -x .svn -x configure -x libtool -x stamp-h1 ./wsf_c/ ../wsfcpp-trunk.origin/wsf_c/ 2>/dev/null
