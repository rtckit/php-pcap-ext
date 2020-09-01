PHP_ARG_ENABLE([pcap],
  [whether to enable pcap support],
  [AS_HELP_STRING([--enable-pcap],
    [Enable pcap support])],
  [no])

if test "$PHP_PCAP" != "no"; then
  PHP_NEW_EXTENSION(pcap, pcap.c, $ext_shared)

  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

  AC_MSG_CHECKING(for libpcap)

  if test $PHP_PCAP == "yes" && test -x "$PKG_CONFIG" && $PKG_CONFIG --exists libpcap; then
    if $PKG_CONFIG libpcap --atleast-version 1.8.0; then
      LIBPCAP_INCLINE=`$PKG_CONFIG libpcap --cflags`
      LIBPCAP_LIBLINE=`$PKG_CONFIG libpcap --libs`
      LIBPCAP_VERSION=`$PKG_CONFIG libpcap --modversion`
      AC_MSG_RESULT(from pkgconfig: found version $LIBPCAP_VERSION)
      AC_DEFINE(HAVE_PCAPLIB,1,[ ])
    else
      AC_MSG_ERROR(system libpcap must be upgraded to version >= 1.8.0)
    fi
    PHP_EVAL_LIBLINE($LIBPCAP_LIBLINE, PCAP_SHARED_LIBADD)
    PHP_EVAL_INCLINE($LIBPCAP_INCLINE)

  else
    SEARCH_PATH="/usr/local /usr"
    SEARCH_FOR="/include/pcap.h"
    if test -r $PHP_PCAP/$SEARCH_FOR; then # path given as parameter
      PCAP_DIR=$PHP_PCAP
      AC_MSG_RESULT(from option: found in $PCAP_DIR)
    else # search default path list
      for i in $SEARCH_PATH ; do
        if test -r $i/$SEARCH_FOR; then
          PCAP_DIR=$i
          AC_MSG_RESULT(from default path: found in $i)
        fi
      done
    fi
    PHP_ADD_INCLUDE($PCAP_DIR/include)
    PHP_CHECK_LIBRARY(pcap, pcap_version,
    [
      PHP_ADD_LIBRARY_WITH_PATH(pcap, $PCAP_DIR/$PHP_LIBDIR, PCAP_SHARED_LIBADD)
      AC_DEFINE(HAVE_PCAPLIB,1,[ ])
    ],[
      AC_MSG_ERROR([wrong pcap library version or library not found])
    ],[
      -L$PCAP_DIR/$PHP_LIBDIR -lm
    ])
  fi

  PHP_SUBST([CFLAGS])
    PHP_SUBST(PCAP_SHARED_LIBADD)
fi
