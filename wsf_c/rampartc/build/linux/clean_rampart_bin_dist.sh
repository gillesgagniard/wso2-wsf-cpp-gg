#!/bin/bash
echo "Rampart/C binary dest cleaner"
R_HOME=$AXIS2C_HOME

echo "Remove module"
rm -rf  $R_HOME/modules/rampart
rm -rf  $R_HOME/modules/rahas

echo "Remove sample service"
rm -rf $R_HOME/services/sec_echo
rm -rf $R_HOME/services/secconv_echo
rm -rf $R_HOME/services/saml_sts

echo "Remove libs"
rm $R_HOME/lib/librampart.*

echo "Remove sample binaries"
rm -rf $R_HOME/samples/bin/rampartc
rm -rf $R_HOME/samples/lib/rampartc
rm -rf $R_HOME/samples/src/rampartc

echo "Cleaned... :)"

