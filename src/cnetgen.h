// cnetgen.h
//=============================================================================

#if !defined(__cnetgen_h)
# define __cnetgen_h (1)

//-----------------------------------------------------------------------------

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <string.h>
# include <unistd.h>
# include <errno.h>
# include <pthread.h>
# include <syslog.h>
# include <float.h>
# include <sys/syscall.h>
# include <sys/types.h>
# include <sys/ipc.h>
# include <sys/msg.h>
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <inttypes.h>

# define __DHCPSTATS_RUNNING (1) // define to include code to provide running DHCP performance statistics

//-----------------------------------------------------------------------------
/* Quick and simple UI postbox. This can be improved. */

#define MAX_URL (1024) // length of maximum URL we accept
// "wc -L unsafe.txt" currently shows a max URL length of 651-characters

typedef enum {
    E_UNUSED = 0,
    E_HTTP, // HTTP worker individual test pass/fail
    E_MDNS, // mDNS worker individual test pass/fail
    E_DHCP, // DHCP worker individual test pass/fail
    E_HTTP_URL, // HTTP about to fetch from URL
    E_HTTP_URLLE, // HTTP last error URL
    E_HTTP_ITERATION, // HTTP starting new iteration
    E_MDNS_ITERATION, // mDNS starting new iteration
    E_DHCP_TXT, // DHCP log text
    E_DHCP_STATS, // DHCP statistics
    E_FATAL, // FATAL internal error
} worker_e;

typedef struct msgui {
    long mtype;
    union {
        int pass; // 0 == fail, non-zero marks pass
        char url[MAX_URL + 1];
        char txt[128 + 1];
        char err[128 + 1];
    } u;
} msgui_t;

//-----------------------------------------------------------------------------

#define MAX_FRAME (576)

typedef enum {
    D_UNUSED = 0,
    D_READY, // listener ready
    D_FRAME, // DHCP frame from listener
} dhcp_msg_e;

typedef struct msgdhcp {
    long mtype;
    struct {
        struct timespec ts;
        uint32_t xid;
        uint32_t yiaddr;
        uint32_t router_ip;
        uint32_t server_ip;
        uint8_t reason;
        uint8_t shost[ETH_ALEN];
        uint8_t hwaddr[ETH_ALEN];
    } u;
} msgdhcp_t;

//-----------------------------------------------------------------------------

typedef struct statistics_uint {
    uint64_t total;
    uint32_t min;
    uint32_t max;
    uint32_t count;
} statistics_uint_t;

typedef struct statistics_dbl {
    double total;
    double min;
    double max;
    uint32_t count; // count of successful operations
} statistics_dbl_t;

//-----------------------------------------------------------------------------

typedef struct interface {
    struct interface *p_next; // pointer to next descriptor or NULL
    const char *p_iface; // pointer to NUL terminated network interface name
} interface_t;

//-----------------------------------------------------------------------------

typedef enum {
    UT_DEFAULT = 0, // no specific test validation performed
    UT_SAFE, // we expect an OK fetch from this URL
    UT_UNSAFE // we expect a block-page return for this URL
} urltest_e;

typedef struct strlist {
    struct strlist *p_next; // pointer to next element in list chain
    const char *p_str; // pointer to NUL terminated ASCII string
    urltest_e test; // type of testing to perform on the URL
    // serialisation:
    pthread_mutex_t mutex;
    // statistics
    statistics_uint_t stats_amount;
    statistics_dbl_t stats_time_total;
    statistics_dbl_t stats_time_dns;
    statistics_dbl_t stats_time_connect;
} strlist_t;

//-----------------------------------------------------------------------------

typedef struct dhcppriv {
    statistics_uint_t stats_total; // DISCOVER->ACK milliseconds
    statistics_uint_t stats_offer; // DISCOVER->OFFER milliseconds
    statistics_uint_t stats_ack; // REQUEST->ACK milliseconds
} dhcppriv_t;

//-----------------------------------------------------------------------------

typedef struct common {
    // control
    int terminate; // non-zero to terminate all children
    // arguments
    uint32_t clients_http;
    uint32_t clients_mdns;
    uint32_t clients_dhcp;
    uint32_t threads_dhcp;
    interface_t *p_interfaces; // NULL terminated list of interface names
    const char *p_hwiface; // explicit H/W interface to use for DHCP testing
    uint32_t delay_common; // milliseconds between operations (unless overridden)
    uint32_t delay_http; // milliseconds between HTTP operations
    uint32_t delay_mdns; // milliseconds between mDNS operations
    uint32_t delay_dhcp; // milliseconds between DHCP operations
    uint32_t timeout_http; // milliseconds timeout for individual HTTP operations
    uint32_t timeout_mdns; // milliseconds timeout for individual mDNS operations
    uint32_t timeout_dhcp; // milliseconds timeout for individual DHCP operations
    uint32_t count_dhcp; // number of interfaces to simulate for each --dhcp_clients specified
    uint32_t stagger; // milliseconds between thread creation to create some stagger
    uint32_t log_level; // verbosity level
    int silent; // non=zero for "silent" operation
    int ncurses; // non-zero for ncurses "UI"
    // msg queue
    int qid; // worker->UI message queue handle
    int qid_dhcp; // DHCP specific listener->process message queue handle
    uint32_t http_iters;
    uint32_t http_pass;
    uint32_t http_fail;
    uint32_t mdns_iters;
    uint32_t mdns_pass;
    uint32_t mdns_fail;
    uint32_t dhcp_pass;
    uint32_t dhcp_fail;
    // workers
    pthread_t *tid_http;
    pthread_t *tid_mdns;
    pthread_t *tid_dhcp;
    // worker -> display data:
    worker_e type;
    int ok; // non-zero if operation passed, or zero for failure
} common_t;

//-----------------------------------------------------------------------------

typedef struct sockset {
    unsigned int num; // number of sockets (length of vector)
    int *p_svec; // pointer to "num" length vector of socket descriptors
} sockset_t;

//-----------------------------------------------------------------------------

typedef struct dataset {
    common_t *p_common;
    strlist_t *p_head; // pointer to NULL terminated list of entries to iterate through
    size_t entries; // number of elements in the referenced list
    union {
        void *p_private;
        uint64_t arg0;
    } u;
} dataset_t;

//-----------------------------------------------------------------------------

typedef struct internal {
    common_t *p_common;
    void *p_ctx; // opaque internal context
} internal_t;

//-----------------------------------------------------------------------------

#define MACFORM "%02X:%02X:%02X:%02X:%02X:%02X"
#define MACADDR(m) ((unsigned char *)m)[0],((unsigned char *)m)[1],((unsigned char *)m)[2],((unsigned char *)m)[3],((unsigned char *)m)[4],((unsigned char *)m)[5]

extern void log_printf(int priority,const char *fmt,...);
extern uint16_t pthread_prbs15(void);
extern int mswait(uint32_t msecs);
extern void stats_update_uint(statistics_uint_t *p_stats,uint32_t amount);
extern void postmsg(int qid,void *p_msg,size_t msgsz);
extern void vprintpost(int qid,worker_e type,const char *p_format,va_list ap);
extern void printpost(int qid,worker_e type,const char *p_format,...);
extern void uipost(int qid,worker_e type,int ok);

//-----------------------------------------------------------------------------

extern void *thread_http(void *p_priv);
extern void *thread_mdns(void *p_priv);
extern void *thread_dhcp(void *p_priv);

//-----------------------------------------------------------------------------

extern int pktudp(int sockfd,in_addr_t daddr,uint16_t dport,const uint8_t *p_datagram,uint32_t dlen);

//-----------------------------------------------------------------------------

#define AS_NANOSECONDS(t) (uint64_t)(((uint64_t)((t)->tv_sec) * (uint64_t)1000000000L) + (t)->tv_nsec)
#define AS_MILLISECONDS(n) (uint32_t)((n) / (1000 * 1000))

//-----------------------------------------------------------------------------

#endif // !__cnetgen_h

//=============================================================================
// EOF cnetgen.h
