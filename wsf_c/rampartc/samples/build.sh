#!/bin/bash
./autogen.sh
./configure --prefix=${AXIS2C_HOME} --enable-static=no --with-axis2=${AXIS2C_HOME}/include/axis2-1.6.0
make
make install
cd secpolicy
sh deploy.sh scenario5
cd ../
echo "Copying server's axis2.xml to " $AXIS2C_HOME
cp ./data/server_axis2.xml $AXIS2C_HOME/axis2.xml
echo "samples successfuly build. To run echo client cd to client/sec_echo and run update_n_run.sh"
