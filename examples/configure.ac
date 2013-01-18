dnl run autogen.sh to generate the configure script.

AC_PREREQ(2.59)

AC_INIT(wsfcpp-samples-src, 2.1.0)
AC_CANONICAL_SYSTEM
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([tar-ustar])
dnl AM_INIT_AUTOMAKE
AC_PREFIX_DEFAULT(/usr/local/wsf_cpp)
m4_ifdef([_A][M_PROG_TAR],[_A][M_SET_OPTION([tar-ustar])])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

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
    ;;
  *)
    AC_MSG_RESULT(yes)
    NTLM_WRAPPER_DIR="libntlm"
    NTLM_DIR="ntlm"
    CFLAGS="$CFLAGS -DAXIS2_LIBNTLM_ENABLED -DAXIS2_NTLM_ENABLED"
    CPPFLAGS="$CPPFLAGS $NTLM_CFLAGS -DAXIS2_LIBNTLM_ENABLED -DAXIS2_NTLM_ENABLED"
    LDFLAGS="$LDFLAGS $NTLM_LDFLAGS"
    NTLM_LIB="./ntlm/libntlm/libaxis2_ntlm.la"
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
    ;;
  *)
    AC_MSG_RESULT(yes)
    SECURITY_SAMPLE_DIR="callbacks"
    ;;
  esac ],
  AC_MSG_RESULT(yes)
  SECURITY_SAMPLE_DIR="callbacks"
)

#CFLAGS="$CFLAGS -ansi -Wall -D_LARGEFILE64_SOURCE -Wno-implicit-function-declaration"
CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE"
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -ansi -Wall  -Wno-implicit-function-declaration -g"
fi
LDFLAGS="$LDFLAGS -lpthread"

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h string.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_SUBST(NTLM_DIR)
AC_SUBST(NTLM_LIB)
AC_SUBST(SECURITY_SAMPLE_DIR)


AC_CONFIG_FILES([Makefile \
    clients/Makefile \
    clients/echo/Makefile \
    clients/ntlm/Makefile \
    clients/flickr/Makefile \
    clients/math/Makefile \
    clients/mtom/Makefile \
    clients/mtom/resources/Makefile \
    clients/notify/Makefile \
    clients/yahoo/Makefile \
    clients/google/Makefile \
    services/Makefile \
    services/echo/Makefile \
    services/math/Makefile \
    services/mtom/Makefile \
    services/notify/Makefile \
    services/version/Makefile \
    callbacks/Makefile \
    callbacks/authentication_provider/Makefile \
    callbacks/password_callback/Makefile \
    callbacks/replay_detector/Makefile \
    callbacks/sct_provider/Makefile \
    trader/Makefile \
    trader/util/Makefile \
    trader/client/Makefile \
    trader/exchange/Makefile \
    trader/trader/Makefile \
    trader/trader/trader-util/Makefile \
    trader/trader/trader-client/Makefile  
    ])
    
AC_OUTPUT
