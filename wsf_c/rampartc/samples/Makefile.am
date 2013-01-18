TESTS =
datadir=$(prefix)/samples/src/rampartc/secpolicy
SUBDIRS = callback client server keys authn_provider credential_provider data replay_detector sct_provider
data_DATA=

install-data-hook:
	cp -rf secpolicy/* $(datadir)
	find $(datadir) -type d -name ".svn" | xargs rm -rf

EXTRA_DIST=secpolicy omxmlsec data ABOUT_SAMPLES build.sh


