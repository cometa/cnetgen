# Process this file with autoconf to produce a configure script.

AC_INIT([cnetgen],[1.0],[jsmith@rallysmith.co.uk])
AM_INIT_AUTOMAKE

AC_PREFIX_DEFAULT(/usr)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

# Explicit OpenSSL and libcurl versions required:
PKG_CHECK_MODULES([LOCSSL],[openssl >= 1.1.0g])
PKG_CHECK_MODULES([CURL],[libcurl >= 7.56.1])

# NASTY but quick. Ideally we should have a macro like
# PKG_CHECK_MODULES above that will use pkg-config to get the
# information.
#  `pkg-config --libs-only-L libcurl` -l:libcurl.a -lrtmp -lssh2 -lz `pkg-config --libs-only-L openssl` -l:libssl.a -l:libcrypto.a -ldl
#
AC_SUBST([CNG_STATICLIBS],["-L\$(abs_top_builddir)/dependencies/install_curl/lib -l:libcurl.a -lrtmp -lssh2 -lz -L\$(abs_top_builddir)/dependencies/install_openssl/lib -l:libssl.a -l:libcrypto.a -ldl"])

AC_ARG_ENABLE([debug],
    [  --enable-debug          build with additional debugging code],
    [CFLAGS='-g -O0'])

# Checks for libraries.
AC_CHECK_LIB([pthread],[pthread_rwlock_wrlock])
AC_CHECK_LIB([pcap],[pcap_open_live])
AC_CHECK_LIB([ncurses],[initscr])
AC_CHECK_LIB([idn2],[idn2_lookup_ul])

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h stddef.h stdarg.h string.h])
AC_CHECK_HEADERS([time.h errno.h ctype.h unistd.h signal.h limits.h getopt.h fcntl.h syslog.h mntent.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([float.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_TYPE_PID_T

# Checks for library functions.
AC_CHECK_FUNCS([malloc calloc free])
AC_CHECK_FUNCS([strcasecmp strchr strcmp strerror strlen strncpy strstr strtoul strtoull sscanf strdup])
AC_CHECK_FUNCS([time clock_nanosleep])
AC_CHECK_FUNCS([getopt_long])
AC_CHECK_FUNCS([exit fork ioctl signal openlog setvbuf])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([clock_gettime])
AC_CHECK_FUNCS([memset])

AC_OUTPUT(Makefile src/Makefile)
