#!/bin/bash
if [ $# -ne 1 ]
then
    echo "Usage : $0 scenarioX"
    exit
fi

INST_DIR=$AXIS2C_HOME
CLIENT_REPO="$INST_DIR/"
SERVICE_HOME="$INST_DIR/services/sec_echo"

#COPYING THE RELEVENT POLICY FILES TO CLIENT AND SERVER


echo "Replacing settings in policy files."
if [ `uname -s` = Darwin ]
then
    sed -e 's,AXIS2C_HOME,'$INST_DIR',g' -e 's,\.so,\.dylib,g' $1/client-policy.xml > $CLIENT_REPO/policy.xml
else
    sed 's,AXIS2C_HOME,'$INST_DIR',g' $1/client-policy.xml > $CLIENT_REPO/policy.xml
fi

echo "Replacing settings in Configuration files."
if [ `uname -s` = Darwin ]
then
    sed -e 's,AXIS2C_HOME,'$INST_DIR',g' -e 's,\.so,\.dylib,g' $1/services.xml > $SERVICE_HOME/services.xml
else
    sed 's,AXIS2C_HOME,'$INST_DIR',g' $1/services.xml > $SERVICE_HOME/services.xml
fi

if [ -e $1/sts.xml ]
then
	if [ `uname -s` = Darwin ]
	then
		    sed -e 's,AXIS2C_HOME,'$INST_DIR',g' -e 's,\.so,\.dylib,g' $1/sts.xml > $SERVICE_HOME/../secconv_echo/services.xml
	else
			sed 's,AXIS2C_HOME,'$INST_DIR',g' $1/sts.xml > $SERVICE_HOME/../secconv_echo/services.xml
	fi
fi

if [ -e $1/rahas_module.xml ]
then
	if [ `uname -s` = Darwin ]
	then
		    sed -e 's,AXIS2C_HOME,'$INST_DIR',g' -e 's,\.so,\.dylib,g' $1/rahas_module.xml > $SERVICE_HOME/../../modules/rahas/module.xml
	else
			sed 's,AXIS2C_HOME,'$INST_DIR',g' $1/rahas_module.xml > $SERVICE_HOME/../../modules/rahas/module.xml
	fi
fi


