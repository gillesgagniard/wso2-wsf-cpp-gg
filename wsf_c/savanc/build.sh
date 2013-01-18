#!/bin/bash
./autogen.sh
./configure --prefix=$AXIS2C_HOME --enable-static=no --enable-xpath --with-axis2=${AXIS2C_HOME}/include/axis2-1.6.0
make -j30
make install
