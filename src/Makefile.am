AUTOMAKE_OPTIONS = subdir-objects
CNG_STATICLIBS = @CNG_STATICLIBS@

BUILDTIMESTAMP=${shell date +%s}
# Following will return tag if in git tree (e.g. "v1.0-4") or use "Unknown" for non-zero response:
GITTAG = ${shell git describe --tags 2> /dev/null; if [ $$? -ne 0 ]; then echo Unknown; fi}

AM_CFLAGS = -Wall -DBUILDTIMESTAMP=${BUILDTIMESTAMP} -DBUILDVERSION=${GITTAG} $(LOCSSL_CFLAGS) $(CURL_CFLAGS)

sbin_PROGRAMS = cnetgen
cnetgen_SOURCES = \
	cnetgen.c \
	loop_http.c \
	loop_mdns.c \
	loop_dhcp.c \
	dhcp-client.c \
	pktraw.c

cnetgen_LDFLAGS = ${CNG_STATICLIBS}
