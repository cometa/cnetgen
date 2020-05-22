/*
 * Simple DHCP Client (heavily modified for cnetgen)
 * License : BSD
 * Author : Samuel Jacob (samueldotj@gmail.com)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#include <net/if_dl.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>

#define __FAVOR_BSD
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdarg.h>

#include "cnetgen.h"

typedef u_int32_t ip4_t;

#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN  64
#define DHCP_FILE_LEN   128
#define MAX_OPTIONS     256

/*
 * http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
 */
typedef struct dhcp
{
    u_int8_t    opcode;
    u_int8_t    htype;
    u_int8_t    hlen;
    u_int8_t    hops;
    u_int32_t   xid;
    u_int16_t   secs;
    u_int16_t   flags;
    ip4_t       ciaddr;
    ip4_t       yiaddr;
    ip4_t       siaddr;
    ip4_t       giaddr;
    u_int8_t    chaddr[DHCP_CHADDR_LEN];
    char        bp_sname[DHCP_SNAME_LEN];
    char        bp_file[DHCP_FILE_LEN];
    uint32_t    magic_cookie;
    u_int8_t    bp_options[0];
} dhcp_t;

#define DHCP_BOOTREQUEST                    1
#define DHCP_BOOTREPLY                      2

#define DHCP_HARDWARE_TYPE_10_EHTHERNET     1

#define MESSAGE_TYPE_PAD                    0
#define MESSAGE_TYPE_REQ_SUBNET_MASK        1
#define MESSAGE_TYPE_ROUTER                 3
#define MESSAGE_TYPE_DNS                    6
#define MESSAGE_TYPE_DOMAIN_NAME            15
#define MESSAGE_TYPE_REQ_IP                 50
#define MESSAGE_TYPE_ADDRESS_TIME           51
#define MESSAGE_TYPE_DHCP                   53
#define MESSAGE_TYPE_DHCP_SERVER            54
#define MESSAGE_TYPE_PARAMETER_REQ_LIST     55
#define MESSAGE_TYPE_END                    255

#define DHCP_OPTION_DISCOVER                1
#define DHCP_OPTION_OFFER                   2
#define DHCP_OPTION_REQUEST                 3
#define DHCP_OPTION_DECLINE                 4
#define DHCP_OPTION_ACK                     5
#define DHCP_OPTION_NAK                     6
#define DHCP_OPTION_RELEASE                 7
#define DHCP_OPTION_INFORM                  8
#define DHCP_OPTION_END                     0xFF

/* new types defined */
#define MESSAGE_TYPE_HOSTNAME                   12
#define MESSAGE_TYPE_VENDOR_CLASS_IDENTIFIER    60
#define MESSAGE_TYPE_CLIENT_IDENTIFIER          61

typedef enum {
    VERBOSE_LEVEL_NONE = 0,
    VERBOSE_LEVEL_ERROR,
    VERBOSE_LEVEL_INFO,
    VERBOSE_LEVEL_DEBUG,
}verbose_level_t;

static const char *decode_dhcp_option(uint8_t option)
{
    const char *p_name = "<Unknown>";

    switch (option) {
    case DHCP_OPTION_DISCOVER: p_name = "DISCOVER"; break;
    case DHCP_OPTION_OFFER:    p_name = "OFFER";    break;
    case DHCP_OPTION_REQUEST:  p_name = "REQUEST";  break;
    case DHCP_OPTION_DECLINE:  p_name = "DECLINE";  break;
    case DHCP_OPTION_ACK:      p_name = "ACK";      break;
    case DHCP_OPTION_NAK:      p_name = "NAK";      break;
    case DHCP_OPTION_RELEASE:  p_name = "RELEASE";  break;
    case DHCP_OPTION_INFORM:   p_name = "INFORM";   break;
    }

    return p_name;
}

static int dhcp_print(common_t *p_common,verbose_level_t vl,const char *fmt,...)
{
    int do_terminate = 0;
    if (vl <= p_common->log_level) {
        va_list ap;
        va_start(ap,fmt);
        vprintpost(p_common->qid,E_DHCP_TXT,fmt,ap);
        va_end(ap);
    }

    return do_terminate;
}

#define PRINT(p_common,vl,fmt,args...)                  \
    do {                                                \
        (void)dhcp_print(p_common,vl,fmt,##args);       \
    } while (0)

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_MAGIC_COOKIE   0x63825363

typedef void (*dhcp_cb)(internal_t *p_int,dhcp_t *dhcp);

typedef struct inflight {
    struct timespec discover;
    struct timespec offer;
    struct timespec request;
    struct timespec ack;
    uint32_t xid;
    uint32_t my_ip;
    uint32_t server_ip;
    uint32_t router_ip;
    uint8_t mac[ETH_ALEN];
    uint8_t fsm;
} inflight_t;

#define FSM_IDLE (0x00)
#define FSM_WAIT_OFFER (0x01)
#define FSM_WAIT_REQUEST (0x02)

typedef struct context {
    common_t *p_common;
    dhcppriv_t *p_exported;
    pthread_t tid_listener;
    uint32_t total;
    uint32_t inflight;
    inflight_t *p_active; // inflight requests
    uint8_t *p_macs;
    pcap_t *pcap_handle;
    uint64_t tend;
    uint32_t xid;
    uint16_t nclients; // number of per-iteration clients 
    uint8_t nmacs; // number of interfaces we simulate
} context_t;

verbose_level_t program_verbose_level = VERBOSE_LEVEL_NONE; // and ideally should NOT be using globals

#if 0
void hexDump(char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}
#endif // boolean

#if 0
/*
 * Print the Given ethernet packet in hexa format - Just for debugging
 */
static void
print_packet(const u_int8_t *data, int len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        if (i % 0x10 == 0)
            printf("\n %04x :: ", i);
        printf("%02x ", data[i]);
    }
}
#endif // boolean

#if 0
/* Print the ip with PRINT function */
static void
print_ip(common_t *p_common,const char *prefix, u_int32_t ip)
{
    char addr[256];
    sprintf(addr, "%u.%u.%u.%u", ip >> 24, ((ip << 8) >> 24), (ip << 16) >> 24, (ip << 24) >> 24);
    PRINT(p_common,VERBOSE_LEVEL_INFO, "%s=%s", prefix, addr);
}
#endif // boolean

/*
 * Return checksum for the given data.
 * Copied from FreeBSD
 */
static unsigned short
in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

static const uint8_t macoui[3] = { 0x22,0x33,0x44 };

/*
 * This function will be called for any incoming DHCP responses
 */
static void dhcp_input(context_t *p_ctx,msgdhcp_t *p_msg,dhcp_t *p_dhcp)
{
    if (p_ctx && p_ctx->p_common && p_msg && p_dhcp) {
        if (ETH_ALEN == p_dhcp->hlen) {
            /* Only accept packets for our interfaces. This is not definitive,
               but just will cut down the vast majority of chaff. */
            if (0 == memcmp(p_dhcp->chaddr,macoui,sizeof(macoui))) {
                common_t *p_common = p_ctx->p_common;
                u_int8_t *opt;
                u_int8_t code;

                memcpy(p_msg->u.hwaddr,p_dhcp->chaddr,ETH_ALEN);

                p_msg->u.xid = ntohl(p_dhcp->xid);
                p_msg->u.yiaddr = ntohl(p_dhcp->yiaddr);

                /* parse DHCP options to obtain the router ip */
                opt = p_dhcp->bp_options;
                while ((code = *opt++) != MESSAGE_TYPE_END) {
                    switch (code) {
                    case MESSAGE_TYPE_PAD:
                        break;

                    case MESSAGE_TYPE_DHCP:
                        p_msg->u.reason = opt[1];
                        goto inc;

                    case MESSAGE_TYPE_ROUTER:
                    {
                        ip4_t ip;

                        memcpy(&ip,(opt + 1),sizeof(ip));
                        p_msg->u.router_ip = ntohl(ip);
                    }
                    goto inc;

                    case MESSAGE_TYPE_DHCP_SERVER:
                    {
                        ip4_t ip;

                        memcpy(&ip,(opt + 1),sizeof(ip));
                        p_msg->u.server_ip = ntohl(ip);
                    }
                    goto inc;

                    default:
                        PRINT(p_common,VERBOSE_LEVEL_DEBUG,"Ignoring MESSAGE_TYPE %d",code);
                        // fall through ...
                    case MESSAGE_TYPE_DNS: // ignored
                    case MESSAGE_TYPE_REQ_SUBNET_MASK: // ignored
                    case MESSAGE_TYPE_ADDRESS_TIME: // ignored
                    inc:
                        opt += (*opt + 1); /* increment option length */
                        break;
                    }
                }

                postmsg(p_common->qid_dhcp,(void *)p_msg,sizeof(p_msg->u));
            }
        }
    }

    return;
}

/*
 * UDP packet handler
 */
static void udp_input(context_t *p_ctx,msgdhcp_t *p_msg,struct udphdr *udp_packet)
{
    /* Check if there is a response from DHCP server by checking the source Port */
    if (ntohs(udp_packet->uh_sport) == DHCP_SERVER_PORT) {
        dhcp_input(p_ctx,p_msg,(dhcp_t *)((char *)udp_packet + sizeof(struct udphdr)));
    }
    return;
}

/*
 * IP Packet handler
 */
static void ip_input(context_t *p_ctx,msgdhcp_t *p_msg,struct ip *ip_packet)
{
    /* Care only about UDP - since DHCP sits over UDP */
    if (ip_packet->ip_p == IPPROTO_UDP) {
        udp_input(p_ctx,p_msg,(struct udphdr *)((char *)ip_packet + sizeof(struct ip)));
    }
    return;
}

/*
 * Ethernet packet handler
 */
static void
ether_input(u_char *args, const struct pcap_pkthdr *header, const u_char *frame)
{
    context_t *p_ctx = (context_t *)args;
    common_t *p_common = p_ctx->p_common;

    struct ether_header *eframe = (struct ether_header *)frame;

    /* The decision to parse the packets in this capture loop has been taken
       rather than copying the whole-frame through the message interface. */

    if (ETHERTYPE_IP == htons(eframe->ether_type)) {
        msgdhcp_t msg;

        (void)memset(&msg,'\0',sizeof(msg)); // for valgrind
        msg.mtype = D_FRAME;

        if (0 != clock_gettime(CLOCK_MONOTONIC_RAW,&msg.u.ts)) {
            PRINT(p_common,VERBOSE_LEVEL_DEBUG, "Failed to read timestamp: %d (%s)",errno,strerror(errno));
            // Even though we zero above, the function may have had side-effects:
            msg.u.ts.tv_sec = 0;
            msg.u.ts.tv_nsec = 0;
        }

        memcpy(msg.u.shost,eframe->ether_shost,ETH_ALEN);

        ip_input(p_ctx,&msg,(struct ip *)(frame + sizeof(struct ether_header)));
    }

    return;
}

/*
 * Ethernet output handler - Fills appropriate bytes in ethernet header
 */
static void
ether_output(internal_t *p_dhcp,u_char *frame, u_int8_t *mac, int len)
{
    int result;
    struct ether_header *eframe = (struct ether_header *)frame;

    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO,"%s: src MAC %02X:%02X:%02X:%02X:%02X:%02X len %d",__func__,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],len);

    memcpy(eframe->ether_shost, mac, ETHER_ADDR_LEN);
    memset(eframe->ether_dhost, -1,  ETHER_ADDR_LEN);
    eframe->ether_type = htons(ETHERTYPE_IP);

    len = len + sizeof(struct ether_header);

    /* Send the packet on wire */
    if (p_dhcp && p_dhcp->p_ctx) {
        context_t *p_ctx = (context_t *)p_dhcp->p_ctx;

        result = pcap_inject(p_ctx->pcap_handle,frame,len);
        PRINT(p_dhcp->p_common,VERBOSE_LEVEL_DEBUG,"Send %d bytes",result);
        if (result <= 0) {
            pcap_perror(p_ctx->pcap_handle,"ERROR:");
        }
    }
}

/*
 * IP Output handler - Fills appropriate bytes in IP header
 */
static void
ip_output(struct ip *ip_header, int *len)
{
    *len += sizeof(struct ip);

    ip_header->ip_hl = 5;
    ip_header->ip_v = IPVERSION;
    ip_header->ip_tos = 0x10;
    ip_header->ip_len = htons(*len);
    ip_header->ip_id = htonl(0xffff);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;
    ip_header->ip_src.s_addr = 0;
    ip_header->ip_dst.s_addr = 0xFFFFFFFF;

    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));
}

/*
 * UDP output - Fills appropriate bytes in UDP header
 */
static void
udp_output(struct udphdr *udp_header, int *len)
{
    if (*len & 1)
        *len += 1;
    *len += sizeof(struct udphdr);

    udp_header->uh_sport = htons(DHCP_CLIENT_PORT);
    udp_header->uh_dport = htons(DHCP_SERVER_PORT);
    udp_header->uh_ulen = htons(*len);
    udp_header->uh_sum = 0;
}

/*
 * DHCP output - Just fills DHCP_BOOTREQUEST
 */
static void dhcp_output(dhcp_t *dhcp,uint32_t xid,u_int8_t *mac,int *len)
{
    *len += sizeof(dhcp_t);
    memset(dhcp, 0, sizeof(dhcp_t));

    dhcp->opcode = DHCP_BOOTREQUEST;
    dhcp->htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp->hlen = 6;
    memcpy(dhcp->chaddr, mac, DHCP_CHADDR_LEN);

    dhcp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    dhcp->xid = htonl(xid);
}

/*
 * Adds DHCP option to the bytestream
 */
static int
fill_dhcp_option(u_int8_t *packet, u_int8_t code, u_int8_t *data, u_int8_t len)
{
    packet[0] = code;
    packet[1] = len;
    memcpy(&packet[2], data, len);

    return len + (sizeof(u_int8_t) * 2);
}

/*
 * Fill DHCP options
 */
static int
fill_dhcp_discovery_options(dhcp_t *dhcp, u_int8_t *mac, u_int32_t req_ip, const char* vend_str, const char* host_name, u_int8_t* parameter_req_custom, int num_parameter_reqs)
{
    int len = 0;
    u_int8_t parameter_req_list[] = {MESSAGE_TYPE_REQ_SUBNET_MASK, MESSAGE_TYPE_ROUTER, MESSAGE_TYPE_DNS, MESSAGE_TYPE_DOMAIN_NAME};
    u_int8_t option;
    u_int8_t client_ident[7];

    option = DHCP_OPTION_DISCOVER;
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP, &option, sizeof(option));

    /* LK: Add hostname */
    if (host_name) {
        len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_HOSTNAME, (u_int8_t *)host_name, strlen(host_name));
    }

    /* LK: Add requested IP (not gaurenteed) */
    if (req_ip != 0) {
        len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_REQ_IP, (u_int8_t *)&req_ip, sizeof(req_ip));
    }

    if (num_parameter_reqs > 0) { /* LK: use a custom request list */
        len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_PARAMETER_REQ_LIST, (u_int8_t *)parameter_req_custom, num_parameter_reqs * sizeof(u_int8_t));
    }
    else { /* LK: use a standard request list */
        len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_PARAMETER_REQ_LIST, (u_int8_t *)&parameter_req_list, sizeof(parameter_req_list));
    }

    /* LK: ADD VENDOR CLASS IDENTIFIER and CLIENT IDENTIFIER */
    if (vend_str) {
        len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_VENDOR_CLASS_IDENTIFIER, (u_int8_t *)vend_str, strlen(vend_str));
    }

    /* LK: set the hardware identifier for client ident */
    client_ident[0] = 1;
    memcpy(&client_ident[1], mac, 6);
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_CLIENT_IDENTIFIER, (u_int8_t *)&client_ident, 7);

    option = 0;
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_END, &option, sizeof(option));

    return len;
}

/*
 * Send DHCP DISCOVERY packet
 */
static int dhcp_discovery(internal_t *p_dhcp,inflight_t *p_req,u_int32_t req_ip,const char *vend_str,const char *host_name,u_int8_t *parameter_req_custom,int num_parameter_reqs)
{
    u_int8_t *mac = p_req->mac;

    /* We set this FSM *BEFORE* we transmit to ensure we have the state if the
       listener processes the packet before our code finishes. The current
       single msg receiver implementation (this thread) means we cannot get out
       of sync. This is just safety in-case the code is ever re-engineered. */
    p_req->fsm = FSM_WAIT_OFFER;

    int len = 0;
    char packet[4096] = {0};
    struct udphdr *udp_header;
    struct ip *ip_header;
    dhcp_t *dhcp;

    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO, "Sending DHCP_DISCOVERY MAC: " MACFORM "",MACADDR(mac));

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    udp_header = (struct udphdr *)(((char *)ip_header) + sizeof(struct ip));
    dhcp = (dhcp_t *)(((char *)udp_header) + sizeof(struct udphdr));

    len = fill_dhcp_discovery_options(dhcp, mac, req_ip, vend_str, host_name, parameter_req_custom, num_parameter_reqs);

    dhcp_output(dhcp,p_req->xid,mac,&len);
    udp_output(udp_header, &len);
    ip_output(ip_header, &len);
    ether_output(p_dhcp,(u_char *)packet,mac,len);

    if (0 != clock_gettime(CLOCK_MONOTONIC_RAW,&(p_req->discover))) {
        p_req->discover.tv_sec = 0;
        p_req->discover.tv_nsec = 0;
    }

    return 0;
}

static int
fill_dhcp_options(dhcp_t *dhcp, u_int32_t req_ip, u_int32_t server_ip,uint8_t option)
{
    int len = 0;
    ip4_t ip;

    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP, &option,
        sizeof(option));

    ip = htonl(server_ip);
    len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_DHCP_SERVER,
        (u_int8_t *)&ip, sizeof(ip4_t));

    if (DHCP_OPTION_REQUEST == option) {
        ip = htonl(req_ip);
        len += fill_dhcp_option(&dhcp->bp_options[len], MESSAGE_TYPE_REQ_IP,
                                (u_int8_t *)&ip, sizeof(ip4_t));
    }

    dhcp->bp_options[len] = MESSAGE_TYPE_END;
    len++;

    return len;
}

static void dhcp_op(internal_t *p_dhcp,inflight_t *p_req,uint8_t option)
{
    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO,"%s: src MAC " MACFORM "",__func__,MACADDR(p_req->mac));

    int len = 0;
    char packet[4096] = {0};
    struct udphdr *udp_header;
    struct ip *ip_header;
    dhcp_t *dhcp;

    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO,"Sending DHCP %u %s",option,decode_dhcp_option(option));

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    udp_header = (struct udphdr *)(((char *)ip_header) + sizeof(struct ip));
    dhcp = (dhcp_t *)(((char *)udp_header) + sizeof(struct udphdr));

    len = fill_dhcp_options(dhcp,p_req->my_ip,p_req->server_ip,option);

    dhcp_output(dhcp,p_req->xid,p_req->mac,&len);
    dhcp->yiaddr = 0;
    dhcp->siaddr = 0;

    switch (option) {
    case DHCP_OPTION_REQUEST:
        p_req->fsm = FSM_WAIT_REQUEST;
        break;

    case DHCP_OPTION_RELEASE:
        dhcp->ciaddr = htonl(p_req->my_ip);
        break;

    default:
        // NOP
        break;
    }

    udp_output(udp_header,&len);
    ip_output(ip_header,&len);
    ether_output(p_dhcp,(u_char *)packet,p_req->mac,len);

    if (DHCP_OPTION_REQUEST == option) {
        if (0 != clock_gettime(CLOCK_MONOTONIC_RAW,&(p_req->request))) {
            p_req->request.tv_sec = 0;
            p_req->request.tv_nsec = 0;
        }
    }

    return;
}

/* parse a comma separated list of ints into an array, will validate alone the way */
int parseInputDHCPOptions(const char* dhcpopts, u_int8_t* input_arr) {
    char seps[] = ",";
    char* token;
    int var;
    int i = 0;
    char *option_copy = NULL;
    int found_error = 0;

    option_copy = strdup(dhcpopts);
    if (option_copy == NULL) {
        return -1;
    }

    token = strtok (option_copy, seps);
    while (token != NULL) {
        var = atoi(token);
        if (var <= 0 || var > 255)
            found_error = 1; //didn't correctly parse a list value
        input_arr[i++] = (u_int8_t)var;  //explicitly cast to smaller type
        token = strtok (NULL, seps);
    }

    free(option_copy);
    if (found_error)
        return 0;
    else
        return i; //size of options array
}

//-----------------------------------------------------------------------------

static void report_error(int qid,const char *p_emsg)
{
    printpost(qid,E_FATAL,"%s",p_emsg);
    return;
}

//-----------------------------------------------------------------------------

static void pcap_close_and_report(int qid,pcap_t *p_handle)
{
    const char *p_err = NULL;
    const char *p_pce = pcap_geterr(p_handle);

    if (p_pce) {
        p_err = strdup(p_pce);
    }
    pcap_close(p_handle);
    if (p_err) {
        report_error(qid,p_err);
        (void)free((void *)p_err);
    }
    return;
}

//-----------------------------------------------------------------------------

int dhcp_client(internal_t *p_dhcp)
{
    int rcode = 0;

    if (p_dhcp && p_dhcp->p_ctx) {
        context_t *p_ctx = (context_t *)p_dhcp->p_ctx;
        uint8_t lmac[ETH_ALEN]; // filled with MAC for the specific operation
        uint32_t midx;

        // Start a fresh test:
        p_ctx->inflight = 0;

        for (midx = 0; (midx < p_ctx->nmacs); midx++) {
            uint16_t cidx;

            // Base interface MAC:
            memcpy(lmac,&p_ctx->p_macs[ETH_ALEN * midx],(sizeof(macoui) + 1));

            for (cidx = 0; (cidx < p_ctx->nclients); cidx++) {
                p_ctx->xid++;

                lmac[4] = (uint8_t)((cidx >> 8) & 0xFF);
                lmac[5] = (uint8_t)((cidx >> 0) & 0xFF);

                // CONSIDER: adding to context_t for testing different settings across iterations
                const char *vend = NULL;
                const char *hostname = NULL;
                u_int8_t dhcp_options_arr[MAX_OPTIONS] = {0};
                int dhcp_options_count = 0;

                inflight_t *p_req = &(p_ctx->p_active[p_ctx->inflight]);
                p_req->xid = p_ctx->xid;
                memcpy(p_req->mac,lmac,ETH_ALEN);
                p_req->fsm = FSM_IDLE;

                /* Send DHCP DISCOVERY packet */
                int result = dhcp_discovery(p_dhcp,p_req,0,vend,hostname,dhcp_options_arr,dhcp_options_count);
                if (result) {
                    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_ERROR,"Could not send DHCP DISCOVERY on device \"%s\"",p_dhcp->p_common->p_hwiface);
                } else {
                    p_ctx->inflight++;
                }
            }
        }
    }

    return rcode;
}

//-----------------------------------------------------------------------------

// NASTY - but a quick solution
pcap_t *dhcp_pcap_handle;
static volatile int dhcp_terminate = 0;

static void *thread_listener(void *p_priv)
{
    context_t *p_ctx = (context_t *)p_priv;
    common_t *p_common = p_ctx->p_common;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
    errbuf[0] = '\0';

    dhcp_pcap_handle = pcap_open_live(p_common->p_hwiface,BUFSIZ,0,0,errbuf);
    if (NULL == dhcp_pcap_handle) {
        report_error(p_common->qid,errbuf);
    } else {
        bpf_u_int32 bpf_net;
        bpf_u_int32 bpf_mask;

        /* We use a filter to cut down on the number of packets processed by
           this code. */

        if (pcap_lookupnet(p_common->p_hwiface,&bpf_net,&bpf_mask,errbuf) < 0) {
            errbuf[sizeof(errbuf) - 1] = '\0';
            report_error(p_common->qid,errbuf);
        } else {
            if (pcap_compile(dhcp_pcap_handle,&bpf,"ip and (udp port 68)",1,bpf_net) < 0) {
                pcap_close_and_report(p_common->qid,dhcp_pcap_handle);
            } else {
                if (pcap_setfilter(dhcp_pcap_handle,&bpf) < 0) {
                    pcap_close_and_report(p_common->qid,dhcp_pcap_handle);
                } else {
                    // POST msg to control thread:
                    {
                        msgdhcp_t msg;

                        (void)memset(&msg,'\0',sizeof(msg)); // for valgrind
                        msg.mtype = D_READY;

                        postmsg(p_common->qid_dhcp,(void *)&msg,sizeof(msg.u));
                    }

                    do {
                        int result = pcap_loop(dhcp_pcap_handle,-1,ether_input,(u_char *)p_ctx);
                        if (-2 == result) {
                            PRINT(p_common,VERBOSE_LEVEL_INFO,"Terminating listener via pcap_breakloop()");
                            break; // while
                        } else if (-1 == result) {
                            pcap_perror(dhcp_pcap_handle,"Listener loop");
                        }
                    } while (1);
                }
            }
        }
    }

    pthread_exit(p_priv);
}

void dhcp_listener_terminate(void)
{
    // thread cancellation
    // thread signalling
    if (dhcp_pcap_handle) {
        pcap_breakloop(dhcp_pcap_handle);
    }
    dhcp_terminate = -1;
    return;
}

//-----------------------------------------------------------------------------

int dhcp_setup(internal_t *p_dhcp,dhcppriv_t *p_exported)
{
    int do_terminate = 0;

    if (NULL == p_dhcp->p_ctx) {
        p_dhcp->p_ctx = calloc(1,sizeof(context_t));
        if (p_dhcp->p_ctx) {
            context_t *p_ctx = (context_t *)p_dhcp->p_ctx; // shorthand
            int result = 0;

            p_ctx->p_common = p_dhcp->p_common;
            p_ctx->p_exported = p_exported;

            {
                pthread_attr_t attr;
                int error;

                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_JOINABLE);

                error = pthread_create(&(p_ctx->tid_listener),&attr,thread_listener,p_ctx);
                if (error) {
                    fprintf(stderr,"Failed to start DHCP listener thread with error %d\n",error);
                }
            }

            p_ctx->xid = (u_int32_t)htonl(syscall(SYS_gettid));

            /* Generate the MAC addresses for the interfaces: */
            {
                uint32_t nmacs = p_dhcp->p_common->count_dhcp;
                if (255 < nmacs) {
                    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO,"Limiting DHCP testing to 255 MACs");
                    nmacs = 255;
                }
                uint8_t *p_macs = calloc(nmacs,ETH_ALEN);
                if (NULL == p_macs) {
                    perror("OOM macs");
                    result = -1;
                } else {
                    unsigned int idx;

                    for (idx = 0; (idx < nmacs); idx++) {
                        uint8_t *mac = &p_macs[idx * ETH_ALEN]; // shorthand
                        pid_t tid = syscall(__NR_gettid);

                        // Fixed (OUI) component of EUI-48:
                        mac[0] = macoui[0]; // marks as locally administered address (bit1 MUST be set)
                        mac[1] = macoui[1];
                        mac[2] = macoui[2];
                        // per-interface:
                        mac[3] = (uint8_t)idx;
                        // filled with per-worker identifier:
                        mac[4] = 0x00;
                        mac[5] = 0x00;

                        PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO,"Interface %3u using base MAC: %02X:%02X:%02X:%02X:%02X:%02X",(unsigned int)tid,idx,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
                    }

                    p_ctx->nmacs = nmacs;
                    p_ctx->p_macs = p_macs;
                }
            }

            {
                p_ctx->nclients = p_dhcp->p_common->clients_dhcp;
                /* It is VERY unlikely we will ever have that number of clients;
                   since we are unlikely to have a DHCP server with a pool this
                   large... but we ensure our internal range is respected: */
                if (((1 << 16) - 1) < p_dhcp->p_common->clients_dhcp) {
                    p_ctx->nclients = ((1 << 16) - 1);
                }
                p_ctx->total = (p_ctx->nmacs * p_ctx->nclients);

                p_ctx->p_active = calloc(p_ctx->total,sizeof(inflight_t));
                if (NULL == p_ctx->p_active) {
                    perror("OOM active");
                    exit(EXIT_FAILURE);
                }
            }

            if (0 == result) {
                char errbuf[PCAP_ERRBUF_SIZE];

                errbuf[0] = '\0';

		/* Open the device and get pcap handle for it */
                /* We use a real (specified) H/W interface: */
                p_ctx->pcap_handle = pcap_open_live(p_dhcp->p_common->p_hwiface,BUFSIZ,1,(int)10,errbuf); // 10ms since we use p_dhcp->p_common->timeout for the pcap_loop timeout
                if (NULL == p_ctx->pcap_handle) {
                    report_error(p_dhcp->p_common->qid,errbuf);
                    do_terminate = -1;
                }
            } else {
                fprintf(stderr,"Unable to set base MAC addresses for all interface\n");
                do_terminate = -1;
            }
        } else {
            fprintf(stderr,"OOM DHCP context_t\n");
            do_terminate = -1;
        }
    }

    return do_terminate;
}

//-----------------------------------------------------------------------------

void dhcp_shutdown(internal_t *p_dhcp)
{
    if (p_dhcp->p_ctx) {
        context_t *p_ctx = (context_t *)p_dhcp->p_ctx;
        int error;
        error = pthread_cancel(p_ctx->tid_listener);
        if (error && (ESRCH != error) ) {
            fprintf(stderr,"Error %d \"%s\" from listener thread cancel\n",error,strerror(error));
        } else {
            void *status = NULL;
            error = pthread_join(p_ctx->tid_listener,&status);
            if (error) {
                if (ESRCH != error) {
                    fprintf(stderr,"Error %d \"%s\" from listener thread join\n",error,strerror(error));
                }
            } else {
                fprintf(stderr,"Completed DHCP listener with status %p\n",status);
            }
        }

        if (p_ctx->p_macs) {
            (void)free(p_ctx->p_macs);
        }
        if (p_ctx->pcap_handle) {
            pcap_close(p_ctx->pcap_handle);
        }
    }

    // We do this to ensure the UI loop terminates too if needed:
    PRINT(p_dhcp->p_common,VERBOSE_LEVEL_NONE,"Terminating");

    return;
}

//-----------------------------------------------------------------------------

static inflight_t *match_inflight(context_t *p_ctx,uint32_t xid,uint8_t *p_mac)
{
    inflight_t *p_match = NULL;
    unsigned int idx;

    for (idx = 0; (idx < p_ctx->total); idx++) {
        inflight_t *p_cptr = &(p_ctx->p_active[idx]); // shorthand
        if ((p_cptr->xid == xid) && (0 == memcmp(p_cptr->mac,p_mac,ETH_ALEN))) {
            p_match = p_cptr;
            break;
        }
    }

    return p_match;
}

//-----------------------------------------------------------------------------

int dhcp_process(internal_t *p_dhcp)
{
    common_t *p_common = p_dhcp->p_common;
    context_t *p_ctx = (context_t *)p_dhcp->p_ctx;
    int do_terminate = 0;

    /* Wait until we have received the required OFFER and ACK/NAK responses
       expected, or we timeout. */
    PRINT(p_common,VERBOSE_LEVEL_NONE,"inflight %u",p_ctx->inflight);

    // How long we wait for:
    {
        struct timespec ts;
        uint64_t pcwait = ((p_common->delay_dhcp < p_common->timeout_dhcp) ? p_common->delay_dhcp : p_common->timeout_dhcp); // shortest

        /* We do not wait for the configured timeout if the inter-gap DHCP test
           delay is shorter, since that means we would have more inflight than
           the rest of the test options are configured for. */
        if (0 == clock_gettime(CLOCK_MONOTONIC_RAW,&ts)) {
            p_ctx->tend = AS_NANOSECONDS(&ts);
            p_ctx->tend += (pcwait * 1000 * 1000);
        }
    }

    // Process responses:
    {
        msgdhcp_t msg;

        do {
            if (dhcp_terminate) {
                do_terminate = -1;
                break; // while
            }
            if (msgrcv(p_common->qid_dhcp,(void *)&msg,sizeof(msg.u),0,(IPC_NOWAIT | MSG_NOERROR)) == -1) {
                if (ENOMSG == errno) {
                    struct timespec ts;
                    if (0 == clock_gettime(CLOCK_MONOTONIC_RAW,&ts)) {
                        if (p_ctx->tend < AS_NANOSECONDS(&ts)) {
                            PRINT(p_dhcp->p_common,VERBOSE_LEVEL_INFO,"timeout");
                            break; // while
                        }
                    }
                } else {
                    fprintf(stderr,"%s: Terminating %d (%s)\n",__func__,errno,strerror(errno));
                    do_terminate = -1;
                }
            } else {
                switch (msg.mtype) {
                case D_FRAME:
                    PRINT(p_common,VERBOSE_LEVEL_INFO,"D_FRAME: %10lu.%lu (from " MACFORM ") " MACFORM " xid %08X reason %02X %s yiaddr %08X router_ip %08X server_ip %08X\n",msg.u.ts.tv_sec,msg.u.ts.tv_nsec,MACADDR(msg.u.shost),MACADDR(msg.u.hwaddr),msg.u.xid,msg.u.reason,decode_dhcp_option(msg.u.reason),msg.u.yiaddr,msg.u.router_ip,msg.u.server_ip);
                    {
                        inflight_t *p_match = match_inflight(p_ctx,msg.u.xid,msg.u.hwaddr);
                        // NOTE: NAK or timeout reported at end of while loop
                        if (p_match) {
                            switch (p_match->fsm) {
                            case FSM_WAIT_OFFER:
                                if (DHCP_OPTION_OFFER == msg.u.reason) {
                                    p_match->offer = msg.u.ts; // OFFER packet time
                                    p_match->my_ip = msg.u.yiaddr;
                                    p_match->server_ip = msg.u.server_ip;
                                    p_match->router_ip = msg.u.router_ip;

                                    dhcp_op(p_dhcp,p_match,DHCP_OPTION_REQUEST);
                                }
                                break;

                            case FSM_WAIT_REQUEST:
                                if (DHCP_OPTION_ACK == msg.u.reason) {
                                    p_match->ack = msg.u.ts; // ACK packet time

                                    uipost(p_common->qid,E_DHCP,-1); // per request PASS notification

                                    dhcp_op(p_dhcp,p_match,DHCP_OPTION_RELEASE);

                                    {
                                        uint64_t ns_discover = AS_NANOSECONDS(&(p_match->discover));
                                        uint64_t ns_offer = AS_NANOSECONDS(&(p_match->offer));
                                        uint64_t ns_request = AS_NANOSECONDS(&(p_match->request));
                                        uint64_t ns_ack = AS_NANOSECONDS(&(p_match->ack));

                                        uint32_t total = AS_MILLISECONDS(ns_ack - ns_discover);
                                        uint32_t offer = AS_MILLISECONDS(ns_offer - ns_discover);
                                        uint32_t ack = AS_MILLISECONDS(ns_ack - ns_request);

                                        dhcppriv_t *p_exported = p_ctx->p_exported; // shorthand
                                        if (p_exported) {
                                            stats_update_uint(&p_exported->stats_total,total);
                                            stats_update_uint(&p_exported->stats_offer,offer);
                                            stats_update_uint(&p_exported->stats_ack,ack);
#if defined(__DHCPSTATS_RUNNING)
                                            printpost(p_common->qid,E_DHCP_STATS,"DISCOVER->OFFER %u/%u/%u : REQUEST->ACK %u/%u/%u : total DISCOVER->ACK %u/%u/%u",
                                                      p_exported->stats_offer.min,(uint32_t)(p_exported->stats_offer.total / p_exported->stats_offer.count),p_exported->stats_offer.max,
                                                      p_exported->stats_ack.min,(uint32_t)(p_exported->stats_ack.total / p_exported->stats_ack.count),p_exported->stats_ack.max,
                                                      p_exported->stats_total.min,(uint32_t)(p_exported->stats_total.total / p_exported->stats_total.count),p_exported->stats_total.max);
#endif // __DHCPSTATS_RUNNING
                                        }
                                    }

                                    // Will clear our gathered timings as well as the state:
                                    memset(p_match,'\0',sizeof(*p_match));
                                    (p_ctx->inflight)--;
                                }
                                break;

                            default:
                                PRINT(p_common,VERBOSE_LEVEL_ERROR,"Unexpected FSM %u",p_match->fsm);
                                break;
                            }

                        } else {
                            PRINT(p_common,VERBOSE_LEVEL_DEBUG,"Did not match");
                        }
                    }
                    break;

                default:
                    PRINT(p_common,VERBOSE_LEVEL_ERROR,"Unrecognised DHCP mtype %ld",msg.mtype);
                    break;
                }
            }
        } while ((0 == do_terminate) && (p_ctx->inflight));
    }

    if (p_ctx->inflight) {
        unsigned int idx;

        //printf("%s: still have %u inflight\n",__func__,p_ctx->inflight);

        for (idx = 0; (idx < p_ctx->inflight); idx++) {
            uipost(p_common->qid,E_DHCP,0); // per request FAIL notification
        }
    }

    PRINT(p_common,VERBOSE_LEVEL_NONE," ",p_ctx->inflight);

    return do_terminate;
}

//-----------------------------------------------------------------------------
// EOF dhcp-client.c
