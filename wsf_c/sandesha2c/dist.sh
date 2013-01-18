#!/bin/bash

rm -rf xdocs/api/html
rm -rf target/docs
maven site
cd xdocs/api
doxygen doxygenconf
cd ../..
cp -r xdocs/api/html target/docs/api/
cp xdocs/docs/mod_log/module.xml target/docs/docs/mod_log
cp -r target/docs sandesha2c-src-0.94

cd samples   
make dist   
tar -xf sandesha2c-src-0.94.tar.gz     
mv  sandesha2c-src-0.94 ../sandesha2c-src-0.94    
cd ../sandesha2c-src-0.94      
mv sandesha2c-src-0.94 samples

for i in `find . -name "*.la"`
do
	rm $i
done

for i in `find . -name "*.a"`
do
	rm $i
done

