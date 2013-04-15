#!/bin/sh
diff -u -r -x "*.Plo" -x "*.la" -x "Makefile*" -x "*.lai" -x "*.o" -x "*.so" -x "*m4*" -x configure ../wsfcpp-trunk.origin/ . 2>/dev/null | grep -v "Only in"
