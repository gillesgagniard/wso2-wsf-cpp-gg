#!/bin/bash
echo "If you do not need to build Rampart/C %sh rampart-bindist nobuild"
BIN_DIR=rampartc-bin-1.3.0-linux
INCL_V_DIR=rampart-1.3.0
TAR_GZ=$BIN_DIR.tar.gz
MD5=$TAR_GZ.md5
PWDIR=$PWD

if [ $# -ne 1 ]
then
    echo "Build Rampart"
    ./build.sh 

    echo "Build samples"
    cd samples
    ./build.sh
    #to get sample sources
    make dist
cd ..

fi


echo "Deleting $BIN_DIR, $TAR_GZ, $MD5 if any"
rm -rf $BIN_DIR
rm $TAR_GZ
rm $MD5

ls 
sleep 1

echo "Creating directories in $PWDIR"
mkdir $BIN_DIR
mkdir $BIN_DIR/samples
mkdir $BIN_DIR/samples/bin
mkdir $BIN_DIR/samples/bin/rampartc
mkdir $BIN_DIR/samples/lib
mkdir $BIN_DIR/samples/lib/rampartc
mkdir $BIN_DIR/samples/src
mkdir $BIN_DIR/samples/src/rampartc
mkdir $BIN_DIR/include
mkdir $BIN_DIR/include/$INCL_V_DIR
mkdir $BIN_DIR/modules
mkdir $BIN_DIR/modules/rampart
mkdir $BIN_DIR/modules/rahas
mkdir $BIN_DIR/lib
mkdir $BIN_DIR/services

echo "Copy related files to $BIN_DIR"
#Copy other related files
cp AUTHORS $BIN_DIR
cp ChangeLog $BIN_DIR
cp COPYING $BIN_DIR
cp INSTALL $BIN_DIR
cp LICENSE $BIN_DIR
cp NEWS $BIN_DIR
cp NOTICE $BIN_DIR
cp README $BIN_DIR

echo "Copy rampart module"
#Copy rampart module
cp -r $AXIS2C_HOME/modules/rampart $BIN_DIR/modules/
cp -r $AXIS2C_HOME/modules/rahas $BIN_DIR/modules/

echo "Copy libraries"
cp -d $AXIS2C_HOME/lib/librampart.* $BIN_DIR/lib

echo "Strip binaries"
strip $BIN_DIR/lib/*.so

echo "Copy samples"
cp -r $AXIS2C_HOME/samples/bin/rampartc/* $BIN_DIR/samples/bin/rampartc/
cp -r $AXIS2C_HOME/samples/lib/rampartc/* $BIN_DIR/samples/lib/rampartc/
cp -r $AXIS2C_HOME/services/sec_echo $BIN_DIR/services/
cp -r $AXIS2C_HOME/services/saml_sts $BIN_DIR/services/
cp -r $AXIS2C_HOME/services/secconv_echo $BIN_DIR/services/

echo "Copy headers"
cp include/*.h $BIN_DIR/include/$INCL_V_DIR

echo "Copy docs"
cp -r target/docs $BIN_DIR/

echo "Copy API"
cp -rf xdocs/api $BIN_DIR/docs

echo "Copy sample sources"
tar -xzf samples/rampart-samples-src*.tar.gz
rm samples/rampart-samples-src*.tar.gz
cp -r rampart-samples-src*/* $BIN_DIR/samples/src/rampartc/
rm -rf rampart-samples-src*
mv $BIN_DIR/samples/src/rampartc/keys $BIN_DIR/samples/src/rampartc/data/

echo "Copy installer script"
cp build/linux/install_rampart_bin_dist.sh  $BIN_DIR/
echo "Copy cleaner script"
cp build/linux/clean_rampart_bin_dist.sh  $BIN_DIR/

echo "Removing garbage in $BIN_DIR"
cd $BIN_DIR

for i in `find . -name "*.svn"`
do
   rm -rf $i
done

for i in `find . -name "*.la"`
do
   rm -rf $i
done

cd $PWDIR
echo "Creating tar.gz in $PWDIR"
tar  -czvf $TAR_GZ $BIN_DIR

echo "Creating MD5"
openssl md5 < $TAR_GZ > $MD5

echo "To sign please enter password for the private key"
gpg --armor --output $TAR_GZ.asc --detach-sig $TAR_GZ

echo "Binary DONE" 
