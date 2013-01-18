#!/bin/bash
set -e
./autogen.sh
./configure --prefix=${AXIS2C_HOME} --enable-static=no --with-axis2=${AXIS2C_HOME}/include/axis2-1.6.0
make
make install
