prglibdir=$(prefix)/services/weather
samplesdir=$(prefix)/samples/server/weather
prglib_LTLIBRARIES = libweather.la
prglib_DATA= services.xml
noinst_HEADERS = weather.h
SUBDIRS =

libweather_la_SOURCES = weather.c weather_skeleton.c

libweather_la_LIBADD  = -L$(AXIS2C_HOME)/lib -lsavan_client

INCLUDES =  @AXIS2INC@ @SAVANINC@

EXTRA_DIST=services.xml
