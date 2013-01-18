dnl run autogen.sh to generate the configure script.

AC_PREREQ(2.59)

AC_INIT(wso2-wsf-cpp-src, 2.1.0)
AC_CANONICAL_SYSTEM
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([tar-ustar])
AC_PREFIX_DEFAULT(/opt/wso2/wsf_cpp)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET



dnl check for flavours of varargs macros (test from GLib)
AC_MSG_CHECKING(for ISO C99 varargs macros in C)
AC_TRY_COMPILE([],[
int a(int p1, int p2, int p3);
#define call_a(...) a(1,__VA_ARGS__)
call_a(2,3);
],axis2c_have_iso_c_varargs=yes,axis2c_have_iso_c_varargs=no)
AC_MSG_RESULT($axis2c_have_iso_c_varargs)

AC_MSG_CHECKING(for GNUC varargs macros)
AC_TRY_COMPILE([],[
int a(int p1, int p2, int p3);
#define call_a(params...) a(1,params)
call_a(2,3);
],axis2c_have_gnuc_varargs=yes,axis2c_have_gnuc_varargs=no)
AC_MSG_RESULT($axis2c_have_gnuc_varargs)

dnl Output varargs tests
if test x$axis2c_have_iso_c_varargs = xyes; then
    AC_DEFINE(HAVE_ISO_VARARGS,1,[Have ISO C99 varargs macros])
fi
if test x$axis2c_have_gnuc_varargs = xyes; then
    AC_DEFINE(HAVE_GNUC_VARARGS,1,[Have GNU-style varargs macros])
fi

dnl Checks for libraries.
AC_CHECK_LIB(dl, dlopen)

if test -d $srcdir/wsf_c; then
    AC_CONFIG_SUBDIRS(wsf_c)
fi


CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE"
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -ansi -Wall  -Wno-implicit-function-declaration -g"
fi
LDFLAGS="$LDFLAGS -lpthread"

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h string.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([net/if.h], [], [],
[#include <stdio.h>
#if STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
# include <stdlib.h>
# endif
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_CHECK_HEADERS([linux/if.h],[],[],
[
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_CHECK_HEADERS([net/if_types.h])
AC_CHECK_HEADERS([net/if_dl.h])

dnl This is a check to see if we are running MacOS X
dnl It may be better to do a Darwin check
AC_CHECK_HEADERS([sys/appleapiopts.h]) 
dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.
dnl AC_FUNC_MALLOC
dnl AC_FUNC_REALLOC
#AC_CHECK_FUNCS([memmove])


abs_top_builddir=`pwd`
AC_SUBST(abs_top_builddir)

AC_ARG_ENABLE(savan, [  --enable-savan  build savan. default=yes])
AC_ARG_ENABLE(libxml2, [  --enable-libxml2      build Libxml2 XML parser library wrapper (default=no)])
AC_ARG_ENABLE(heimdal, [  --enable-heimdal      build heimdal NTLM library wrapper (default=no)])
AC_ARG_ENABLE(libntlm, [  --enable-libntlm      build libntlm NTLM library wrapper (default=no)])
AC_ARG_ENABLE(sandesha, [  --enable-sandesha    build sandesha. default=yes])
AC_ARG_ENABLE(openssl, [  --enable-openssl      enable OpenSSL support in client transport (default=no)])
AC_ARG_ENABLE(wsclient, [  --enable-wsclient    build wsclient. default=yes])
AC_ARG_ENABLE(wsclient, [  --enable-wsclient    build wsclient. default=yes])
AC_ARG_WITH(apr, [  --with-apr[=PATH]      Find the APR header files in 'PATH'. 
	Some Apache2 distributions, specially development versions, 
	install APR (Apache Portable Run-time) include files in a separate location. 
	In that case, to build Apache2 httpd module, this option is also required. 
	'PATH' should point to APR include files location. If you omit the '=PATH' part completely, 
	the configure script will search '/usr/include/apr-0' for APR headers.])

AC_ARG_WITH(apache2,
[  --with-apache2[=PATH]      Find the Apache2 HTTP Web server header files in 'PATH'.
    If this option is given, the Apache2 httpd module would be built.
    'PATH' should point to Apache2 httpd include files location.
    If you omit the '=PATH' part completely, the configure script will search
    '/usr/include/apache2' for Apache2 headers.])

AC_MSG_CHECKING(path to use Axis2C . This is a compulsory to build Sandesha2C)
AC_ARG_WITH(axis2,
[  --with-axis2[=PATH]      use axis2c.],
[ case "$withval" in
  no)
    AC_MSG_RESULT(no)
    ;;
  *)
    AC_MSG_RESULT($withval)
    dnl Find axis2 include dir in the path
    if test -d $withval; then
        AXIS2INC="-I$withval"
    dnl else find the axis2inc include dir in $(WSFCPP_HOME)/include
    elif [ -d "$abs_top_builddir" ]; then
            AXIS2INC="-I$abs_top_builddir/wsf_c/axis2c/include"
    else
        AC_MSG_ERROR(could not find axis2inc. stop)
    fi
    ;; 
  esac ],
  AXIS2INC="-I$abs_top_builddir/wsf_c/axis2c/include"
  AC_MSG_RESULT(no)
)

AC_MSG_CHECKING(whether to build heimdal ntlm wrapper library)
AC_ARG_ENABLE(heimdal, [  --enable-heimdal    
                          build heimdal ntlm library wrapper (default=no)],
[ case "${enableval}" in
  no)
    AC_MSG_RESULT(no)
    NTLM_WRAPPER_DIR=""
    NTLM_DIR=""
    NTLM_LIB=""
    ;;
  *)
    AC_MSG_RESULT(yes)
    NTLM_WRAPPER_DIR="heimdal"
    NTLM_DIR="ntlm"
    #PKG_CHECK_MODULES(HEIMDAL, heimdal-1.4)
    CFLAGS="$CFLAGS -DAXIS2_HEIMDAL_ENABLED -DAXIS2_NTLM_ENABLED"
    CPPFLAGS="$CPPFLAGS $NTLM_CFLAGS -DAXIS2_HEIMDAL_ENABLED -DAXIS2_NTLM_ENABLED"
    LDFLAGS="$LDFLAGS $NTLM_LDFLAGS"
    NTLM_LIB="./ntlm/heimdal/libaxis2_ntlm.la"
    ;;
  esac ],
  AC_MSG_RESULT(no)
)

AC_MSG_CHECKING(whether to build libntlm ntlm wrapper library)
AC_ARG_ENABLE(libntlm, [  --enable-libntlm    
                          build libntlm ntlm library wrapper (default=no)],
[ case "${enableval}" in
  no)
    AC_MSG_RESULT(no)
    NTLM_WRAPPER_DIR=""
    NTLM_DIR=""
    NTLM_LIB=""
    BUILD_NTLM=no
    ;;
  *)
    AC_MSG_RESULT(yes)
    NTLM_WRAPPER_DIR="libntlm"
    NTLM_DIR="ntlm"
    CFLAGS="$CFLAGS -DAXIS2_LIBNTLM_ENABLED -DAXIS2_NTLM_ENABLED"
    CPPFLAGS="$CPPFLAGS $NTLM_CFLAGS -DAXIS2_LIBNTLM_ENABLED -DAXIS2_NTLM_ENABLED"
    LDFLAGS="$LDFLAGS $NTLM_LDFLAGS"
    NTLM_LIB="./ntlm/libntlm/libaxis2_ntlm.la"
    BUILD_NTLM=yes
    ;;
  esac ],
  AC_MSG_RESULT(no)
)

AC_MSG_CHECKING(whether to build rampart)
AC_ARG_ENABLE(rampart, [  --enable-rampart	build rampart. default=yes],
[ case "${enableval}" in
  no)
    AC_MSG_RESULT(no)
    SECURITY_DIR=""
    SECURITY_SAMPLE_DIR=""
    BUILD_RAMPART=no
    ;;
  *)
    AC_MSG_RESULT(yes)
    SECURITY_DIR="security"
    SECURITY_SAMPLE_DIR="callbacks"
    BUILD_RAMPART=yes
    ;;
  esac ],
  AC_MSG_RESULT(yes)
  SECURITY_DIR="security"
  SECURITY_SAMPLE_DIR="callbacks"
  BUILD_RAMPART=yes
)

AXIOMINC="-I$abs_top_builddir/wsf_c/axis2c/axiom/include"
UTILINC="-I$abs_top_builddir/wsf_c/axis2c/util/include"
NEETHIINC="-I$abs_top_builddir/wsf_c/axis2c/neethi/include"

AC_SUBST(SECURITY_DIR)
AC_SUBST(SECURITY_SAMPLE_DIR)
AC_SUBST(BUILD_RAMPART)
AC_SUBST(NTLM_CFLAGS)
AC_SUBST(NTLM_LDFLAGS)
AC_SUBST(NTLM_WRAPPER_DIR)
AC_SUBST(NTLM_DIR)
AC_SUBST(NTLM_LIB)
AC_SUBST(BUILD_NTLM)
AC_SUBST(AXIS2INC)
AC_SUBST(AXIOMINC)
AC_SUBST(UTILINC)
AC_SUBST(NEETIHINC)

export NTLM_LDFLAGS
export NTLM_WRAPPER_DIR
export NTLM_DIR
export NTLM_LIB

export prefix 

AC_CONFIG_FILES([Makefile \
	src/Makefile \
	src/main/Makefile \
	src/msg_recv/Makefile  \
	src/security/Makefile
    ])
    
AC_OUTPUT
