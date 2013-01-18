#!/bin/bash

./autogen.sh

./configure --prefix=${AXIS2C_HOME} --with-axis2=../../axis2c/include --with-savan=../include
make -j10
make install
