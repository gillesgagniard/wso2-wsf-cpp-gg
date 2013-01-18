#!/bin/bash
echo "Rampart/C binary installer"
R_HOME=$AXIS2C_HOME

echo "Copy modules"
cp -r modules/rampart $R_HOME/modules
cp -r modules/rahas $R_HOME/modules

echo "Copy libs"
cp lib/* $R_HOME/lib

echo "Copy sample service"
cp -r services/sec_echo $R_HOME/services
cp -r services/secconv_echo $R_HOME/services
cp -r services/saml_sts $R_HOME/services

echo "Copy samples"
cp -r samples/* $R_HOME/samples/

echo "Copy axis2.xml"
cp samples/src/rampartc/data/server_axis2.xml $R_HOME/axis2.xml

cd samples/src/rampartc/client
sh deploy_client_repo.sh

echo "It's done... :)"

echo "Go to samples/src/rampartc/secpolicy/ and try a scenario"
echo "   %sh test_scen.sh scenarioX server-port"
