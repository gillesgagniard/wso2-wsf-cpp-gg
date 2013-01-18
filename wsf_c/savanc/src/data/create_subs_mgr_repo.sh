SUBS_MGR_HOME="/axis2c/deploy2"

rm -rf $SUBS_MGR_HOME
cp -rf $AXIS2C_HOME $SUBS_MGR_HOME
mv $SUBS_MGR_HOME/services/subscription $SUBS_MGR_HOME/
rm -rf $SUBS_MGR_HOME/services/*
mv $SUBS_MGR_HOME/subscription $SUBS_MGR_HOME/services/

