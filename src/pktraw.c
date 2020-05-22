// pktraw.c
//=============================================================================
/* Simple packet transmission.

   To build standalone test executable:
   gcc -D__STANDALONE -o pktraw pktraw.c
*/
//=============================================================================

#include "cnetgen.h"

//-----------------------------------------------------------------------------
/* Unfortunately AF_PACKET requires elevated priviledges. With it you can use
   SOCK_DGRAM if Ethernet header should be constructed by the socket layer, or
   SOCK_RAW for full packet construction mode.

   Just using AF_INET does not require su priviledges. Also the underlying stack
   will correctly use the multicast MAC address for the destination IP
   address given. */
//-----------------------------------------------------------------------------

int pktudp(int sockfd,in_addr_t daddr,uint16_t dport,const uint8_t *p_datagram,uint32_t dlen)
{
    int success = 0; // default assumes failed
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = dport;
    sin.sin_addr.s_addr = daddr;

#if 0
    {
        unsigned int idx;
        printf("datagram:");
        for (idx = 0; (idx < dlen); idx++) {
            printf(" %02X",p_datagram[idx]);
        }
        printf("\n");
    }
#endif

    // Send the packet
    if (dlen == (uint32_t)sendto(sockfd,p_datagram,dlen,0,(struct sockaddr *)&sin,sizeof(sin))) {
        success = -1;
    }
#if 0
    else {
        perror("sendto");
    }
#endif

    return success;
}

//=============================================================================

#if defined(__STANDALONE)

//-----------------------------------------------------------------------------

// Hardwired example mDNS query packet
static const unsigned char tpkt_mdns[] = {
    0x00,0x00,
    0x00,0x00,
    0x00,0x02, // 2 questions
    0x00,0x00,
    0x00,0x00,
    0x00,0x00,
    /* Q1 "ecospro.local" */
    0x07,0x65,0x63,0x6f,0x73,0x70,0x72,0x6f,
    0x05,0x6c,0x6f,0x63,0x61,0x6c,
    0x00,
    0x00,0x01, // A
    0x00,0x01, // IN
    /* Q2 "ecospro.local" */
    0xc0,0x0c,
    0x00,0x1c, // AAAA
    0x00,0x01  // IN
};

#define DADDR_IPV4 "224.0.0.251"
#define BPORT (5353)

int main(int argc,char **argv)
{
    in_addr_t daddr = inet_addr(DADDR_IPV4);
    uint16_t dport = htons(BPORT);

    int sockfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int ok = pktudp(sockfd,daddr,dport,tpkt_mdns,sizeof(tpkt_mdns));
    printf("%s\n",(ok ? "PASS" : "FAIL"));

    (void)close(sockfd);

    return EXIT_SUCCESS;
}

//-----------------------------------------------------------------------------

#endif // __STANDALONE

//=============================================================================
// EOF pktraw.c
