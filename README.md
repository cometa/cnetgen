# cnetgen Simple network traffic generator

This is just a quickly put together traffic generator test.

## Dependencies

The application currently depends on libcurl, ncurses,
libpcap and pthread support.

```
apt-get update
apt-get install libcurl4-openssl-dev libncurses5-dev libpcap-dev zlib1g-dev librtmp-dev libssh2-1-dev
```

**WARNING** The current *modified* dhcp_client.c implementation uses
libpcap, which in turn requires system priviledges to execute. We
could replace the code with unpriviledged UDP socket operations to
avoid the need for `su` access and libpcap dependency.

For configuration and building a standard autoconf development world
should be installed. e.g.

```
apt-get install autoconf automake libtool pkg-config m4 curl
```

## Static build

To avoid SEGV errors from older, non-thread-safe, OpenSSL
configurations a quick hack to build a mostly-static version of
`cnetgen` against specific suitable versions of OpenSSL and libcurl is
provided:

```
make -f MakeStatic
```

This will download, configure and build static versions of the
required packages and trigger a `PKG_CONFIG_PATH` based configure and
build of `cnetgen`. **NOTE** On a Raspberry Pi 3 a clean MakeStatic
build will take around 20-minutes to complete.

If suitable shared library versions *ARE* available on the build host
then the normal bootstrap, configure process as shown below can be
used.

### Configuration

**WARNING**: Unless you have the development files for `openssl`
version **1.1.0g** or later installed, and the development files for
`libcurl` version **7.56.1** or later installed then **DO NOT**
attempt an autoconf based build as described below. The `configure.ac`
code will STOP the configuration complaining about the available
versions. This is to avoid a build being completed with old, known to
be faulty, versions of those dependencies. If you do use the autoconf
build process below, and you receive warnings about the openssl or
libcurl versions then please just use `make -f MakeStatic` as described
above.

The normal autoconf procedure can be instigated by executing:

```
./bootstrap
./configure
```

If debugging the `cnetgen` binary is intended then you may want to use:

```
./configure --enable-debug
```

This will disable some optimisations, which in turn will make
single-stepping through the code easier to follow.

### Building

```
make
```

# Multiple virtual interfaces

The `cnetmm` script provides a mechanism for creating a set of virtual
interfaces for use by test tools, e.g. `cnetgen`. The benefit being in
providing multiple Ethernet MAC addresses to any network devices
interacted with via the configured interfaces, from the single test
host. For example, this could be useful in testing a network service
can cope with the required/expected number of client devices.

The `cnetmm` script expects a command-line option specifying the
action to be performed:

```
start | stop | status
```

By default (without a `<configfile>` specified) the `cnetmm` will
create a fixed (in the script) number of virtual interfaces:

```
$ sudo ./cnetmm start
$ sudo ./cnetmm status
Active virtual interfaces:
 cnmm0 (dhclient 12923)
 cnmm1 (dhclient 12991)
 cnmm2 (dhclient 13060)
 cnmm3 (dhclient 13130)
```

When the interfaces are no longer needed then the `stop` action will
release the interfaces and terminate the associated DHCP client
processes:

```
$ sudo ./cnetmm stop
Killed old client process
Killed old client process
Killed old client process
Killed old client process
$
$ sudo ./cnetmm status
Not active
$
```

**NOTE**: The local subnet may have a limited size DHCP pool, and
currently `cnetmm` uses DHCP for each virtual interface. So the
(optional) configuration file used with `cnetmm` may need to be tuned
for the subnet configuration the test setup is being used on.

A command-line supplied configuration file can be given to over-ride
the script defaults.

variable | description
-------- | -----------
HWIFACE | The H/W network interface to use for the virtual connections.
VLANS | A bash vector of virtual network interface names
VMACS | An identically sized vector to `VLANS` specifying whether a system supplied MAC address should be used, or an explicit MAC address for that interface instance.
RUNDIR | System directory holding active `cnetmm` state (should not normally need to be overridden).
STATEUP | File marking active `cnetmm` (should not normally need to be overridden).


For example if the following is present in (for example) the file `example.cfg`:

```
HWIFACE=enp3s0
VLANS=(mac0 mac1)
VMACS=(sys 12:34:56:78:9A:BC)
```

then executing:

```
$ sudo ./cnetmm -c example.cfg start
```

will create two virtual interfaces against the named hardware
interface (`HWIFACE`) named `mac0` and `mac1` respectively, with
`mac0` having a system supplied MAC address (the `sys` value), and
with `mac1` using the explicit MAC address supplied. Whether the
virtual interfaces use a system supplied MAC address (`sys`) or an
explicit MAC address is from using the same `VMACS` vector index as in
the `VLANS` vector.

**IMPORTANT** The same configuration file option should be given for
the subsequent `stop` and `status` operations. e.g.:

```
$ sudo ./cnetmm -c example.cfg stop
```

# Usage

## Workers

`http` performs fetches from the supplied list of URLs, receiving the
data and tracking performance per-URL. Each HTTP worker thread will
repeatedly iterate through the supplied URL list, performing one GET
operation and then sleeping for the configured `--delay-http` period.

`mdns` performs broadcast transmits of mDNS queries, with no response
handling. Each mDNS worker thread will repeatedly iterate through the
supplied URL list, triggering one multicast search and then sleeping
for the configured `--delay-mdns` period.

`dhcp` performs DHCP address requests and validates suitable response
and ACK packets. The number of parallel (inflight) active DHCP request
per test iteration is the number of `--dhcp-clients` specified multipled
by the number of interfaces to simulate. The test will sleep for the
configured `--delay-dhcp` period between test iterations.

### Multiple interfaces

If the `cnetmm` script (or any other mechanism, or set of H/W
interfaces) is used then `cnetgen` can be used to spread requests
across a command-line supplied set of interfaces.

The `--interface\-i` command-line option has an extension whereby a
set of comma seperated interfaces can be specified. e.g.

```
-i cnmm0,cnmm1,cnmm2,cnmm3
-i mac0,mac1
-i eth0,vmac0,eth1,eth5
```

The `cnetgen` application will then iterate over the supplied
interface list in each HTTP and mDNS worker thread. For DHCP, since
the interfaces are being used for **real** for the HTTP and mDNS
requests the DHCP requests will come from an internal `cnetgen`
defined MAC address set (currently prefixed `0x22:0x33:0x44` but the
source code can always be changed to use a different locally
administered MAC range if required).

#### DHCP

If the `--dhcp-count` command-line option is NOT specified then the
number of `--interface` interfaces specified on the `cnetgen`
command-line is used as the DHCP interface count. **NOTE** When
`--interface` is being used as the DHCP interface count (i.e. when an
explicit `--dhcp-count` option has not been specified) it is only the
number of interfaces supplied on the command-line that is used, not
the actual interfaces specifed (unlike the HTTP and mDNS workers). The
`--ehw` option specifies the actual interface to be used for the DHCP
packet injection.

The interface count in conjunction with the number of
`--dhcp-clients`, is used as the total count for the inflight DHCP
requests per test iteration **BUT** as mentioned the DHCP requests
will come from a set of internaly manufactured MAC addresses. e.g. the
options:

```
--dhcp-clients 4 --dhcp-count 4 --ehw eth0
```

will result in each DHCP test iteration having **16** inflight DHCP
requests (4 clients multiplied across 4 interfaces) output on hardware
interface eth0 (but with a unique MAC address per request).

**NOTE**: Since the DHCP testing is from a different MAC address set
from the actual virtual interfaces for correct (no error) operation
the network DHCP server must have at least:

```
(#interfaces + (#dhcp-count * #dhcp-clients))
```

free pool entries. So for the `4x4` example above the DHCP server
should have a free pool of 20 addresses available if 4 `--interface`
values are specified. If the DHCP server does not have a large enough
free pool then you should expect to see DHCP failures reported since
there will not be enough addresses to satisfy all of the inflight
requests.

**WARNING** From some basic validity checking with a Comcast DHCP
server it was noticed that the DHCP OFFER responses from the CPE can
be quite slow (>3-seconds). So the `--timeout-dhcp` and
`--delay-dhcp` values should be set accordingly.

## Examples

The `urls.txt` file is an example list of URLs derived from the
`https://github.com/citizenlab/test-lists` english list
`lists/global.csv`.

The `local.txt` file is an example list of mDNS lookup names.

The following example starts 10 DHCP threads against interface
`enp3s0`, and 2 HTTP threads with the `../urls.txt` list. We specify a
10-second (10000ms) timeout for each HTTP worker operation, with a
stagger of 150ms used between worker thread creation (to try and
spread operations across the timespace, rather than having
synchronised startup). Short-hand command-line parameters used:

```
sudo cnetgen -d 10 -e enp3s0 --timeout-http 10000 --stagger 150 -w 2 -u ../urls.txt
```

An example of 5 mDNS threads performing lookups flooding the network
(no delay) would be:
```
cnetgen --mdns-clients 5 --mdns-list local.txt --delay-mdns 0
```

The `--delay` option provides for a global per-iteration delay between
operations within threads. However, if needed each worker type can
have their own delay specified:

option | description
------ | -----------
`--delay-http` | Delay between HTTP operations
`--delay-mdns` | Delay between mDNS operations
`--delay-dhcp` | Delay between DHCP requests

For the HTTP and mDNS workers the delay is used as the gap between
operations within a worker thread as it steps through its list of
supplied test strings. For DHCP testing the delay is the gap between
the configured number of simultaneous DHCP requests (i.e. each DHCP
test iteration will generate `#clients * #interfaces` requests).

The common `--timeout` command-line option has been **deprecated**
(but kept for backwards command-line compatibility). Each worker type
now has the ability to have their own timeout value specified:

option | description
------ | -----------
`--timeout-http` | Timeout for an individual HTTP operation
`--timeout-mdns` | Timeout for mDNS operations. Not currently used
`--timeout-dhcp` | Timeout for **ALL** active (inflight) DHCP requests

### Statistics

Currently on termination, if at least one HTTP client worker has been
started (with the `--http-clients` command-line option) then on
termination a simple CSV dump of the HTTP performance will be
output. Similarly, if enabled, information about the DHCP server
timings will be output too. The user can easily edit the output to
seperate the CSV data into seperate data sets. This information may be
useful to compare timings against different gateway setups.

For example, the following is the head of such an output, and shows
some `http` and `https` operations as well as some failing URLs. The
colums give min/avg/max values for the bytes downloaded, the complete
time taken for the transfer and also the DNS and initial connection
timings. It is followed by the single DHCP timing entry.

```
# HTTP performance:
success_count,transfer_size_min,transfer_size_avg,transfer_size_max,time_transfer_min,time_transfer_avg,time_transfer_max,time_dns_min,time_dns_avg,time_dns_max,time_connect_min,time_connect_avg,time_connect_max,url
2,51046,51046,51046,3.500,4.488,5.476,0.004,0.007,0.011,0.086,0.087,0.088,https://2600.org/
2,138037,138037,138037,0.178,0.184,0.189,0.004,0.004,0.004,0.021,0.021,0.022,http://4genderjustice.org/
2,25442,25442,25442,0.312,0.318,0.325,0.004,0.004,0.004,0.139,0.139,0.139,http://666games.net
2,20103,20103,20103,0.536,0.536,0.536,0.004,0.004,0.004,0.109,0.109,0.109,http://8thstreetlatinas.com
0,,,,,,,,,,,,,http://911lies.org
0,,,,,,,,,,,,,http://abpr2.railfan.net
2,76801,76801,76801,1.144,1.149,1.154,0.000,0.000,0.000,0.000,0.000,0.000,https://addons.mozilla.org
# DHCP performance (12 successful transactions) values in milliseconds:
success_count,offer_min,offer_avg,offer_max,ack_min,ack_avg,ack_max,total_min,total_avg,total_max
12,6,340,1008,19,19,19,26,360,1028

```

This information could prove useful in monitoring the impact of
gateway features on throughput.
