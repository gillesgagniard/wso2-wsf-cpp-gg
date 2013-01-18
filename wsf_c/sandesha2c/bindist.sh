#!/bin/bash
sh clean.sh

AXIS2C_HOME=${AXIS2C_HOME:=`pwd`/deploy}
SANDESHA2C_HOME=`pwd`/deploy
export AXIS2C_HOME
export SANDESHA2C_HOME

echo "Build Sandesha2C"
./autogen.sh
./configure --prefix=${SANDESHA2C_HOME} --enable-static=no --with-axis2=${AXIS2C_HOME}/include/axis2-1.2
make
make install
make dist

echo "Build samples"
cd samples
./autogen.sh
./configure --prefix=${SANDESHA2C_HOME} --with-axis2=${AXIS2C_HOME}/include/axis2-1.2
make
make install
make dist
tar xf sandesha2-sample-src-0.94.tar.gz
mv sandesha2-sample-src-0.94 samples
rm -rf ${SANDESHA2C_HOME}/samples
mv samples ${SANDESHA2C_HOME}

cd ..

rm -rf xdocs/api/html
maven site
cd xdocs/api 
doxygen doxygenconf
cd ../..
cp -r xdocs/api/html target/docs/api/
cp -r target/docs ${SANDESHA2C_HOME}

cd ${SANDESHA2C_HOME}

# rm -rf config.sub missing config.guess depcomp ltmain.sh
for i in `find . -name "*.la"`
do
   rm $i
done

for i in `find . -name "*.a"`
do
   rm $i
done

strip -s ./lib/*
strip -s modules/sandesha2/*

strip -s ./bin/samples/sandesha2/*

rm -rf ./lib/pkgconfig

