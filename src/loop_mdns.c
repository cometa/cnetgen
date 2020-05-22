// loop_mdns.c
//=============================================================================

#include "cnetgen.h"

#include <arpa/nameser.h>

//-----------------------------------------------------------------------------
/* An mDNS Ethernet frame is a multicast UDP packet to:

   MAC address 01:00:5E:00:00:FB (for IPv4) or 33:33:00:00:00:FB (for IPv6)
   IPv4 address 224.0.0.251 or IPv6 address FF02::FB
   UDP port 5353
*/

#define DADDR_IPV4 "224.0.0.251"
#define DADDR_IPV6 "FF02::FB"
#define BPORT (5353)

//-----------------------------------------------------------------------------

static uint32_t build_local_lookup(const char *p_str,uint8_t *p_packet,uint32_t remaining)
{
    uint32_t plen = 0;

    if (remaining >= sizeof(HEADER)) {
        HEADER *p_hdr = (HEADER *)p_packet;
        uint8_t *p_qq = &p_packet[sizeof(*p_hdr)];

        // ensure all flags and count fields are zeroed:
        memset(p_hdr,'\0',sizeof(*p_hdr));

        p_hdr->id = 0;
        p_hdr->qdcount = htons(2); // questions

        remaining -= sizeof(*p_hdr);

        if (remaining) {
            char *p_ctx = NULL;
            char *p_field = strtok_r((char *)p_str,".",&p_ctx);
            uint8_t qused = 0;

            if (p_field) {
                // Q1
                while (p_field) {
                    uint32_t flen = strlen(p_field);

                    if ((flen < NS_MAXLABEL) && (remaining >= (1 + flen))) {
                        *p_qq++ = (uint8_t)flen;
                        memcpy(p_qq,p_field,flen);
                        p_qq += flen;
                        qused += (1 + flen);
                        remaining -= qused;
                    } else {
                        break;
                    }
                    p_field = strtok_r(NULL,".",&p_ctx);
                }

                if (NULL == p_field) {
                    *p_qq++ = 0x00; // terminating NUL
                    qused++;
                    remaining--;

                    if (qused <= NS_MAXLABEL) {
                        if (remaining >= (sizeof(uint16_t) * 2)) {
                            *((uint16_t *)p_qq) = htons(ns_t_a); // A (IPv4 host address)
                            p_qq += sizeof(uint16_t);
                            *((uint16_t *)p_qq) = htons(ns_c_in); // Internet
                            p_qq += sizeof(uint16_t);
                            qused += (sizeof(uint16_t) * 2);
                            remaining -= (sizeof(uint16_t) * 2);

                            // Q2
                            if (remaining >= (sizeof(uint16_t) * 3)) {
                                *p_qq++ = 0xC0; // magic since we KNOW our Q1 is after the header
                                *p_qq++ = 0x0C; // sizeof(*p_hdr)

                                *((uint16_t *)p_qq) = htons(ns_t_aaaa); // AAAA (IPv6 host address)
                                p_qq += sizeof(uint16_t);
                                *((uint16_t *)p_qq) = htons(ns_c_in); // Internet
                                p_qq += sizeof(uint16_t);
                                qused += (sizeof(uint16_t) * 3);
                                remaining -= (sizeof(uint16_t) * 3);

                                plen = sizeof(*p_hdr);
                                plen += qused;
                            }
                        }
                    }
                }
            }
        }
    }

    return plen;
}

//-----------------------------------------------------------------------------

void *thread_mdns(void *p_priv)
{
    dataset_t *p_ds = (dataset_t *)p_priv;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);

    /* We can safely use sendto() from multiple threads on the same socket
       descriptor for our simple UDP packet world. If a different protocol was
       required then we would need to take the hit of per-thread socket
       descriptors. */

    if (p_ds) {
        int local_terminate = 0;
        sockset_t *p_sockset = (sockset_t *)p_ds->u.p_private;
        unsigned int sockidx = 0;
        in_addr_t daddr = inet_addr(DADDR_IPV4);
        uint16_t dport = htons(BPORT);
        strlist_t *p_cptr = NULL;
        uint8_t packet[NS_PACKETSZ]; // should be large enough for our single 2-question queries

        while (0 == local_terminate) {
            int ok;
            int sockfd = p_sockset->p_svec[sockidx];

            sockidx++;
            if (sockidx == p_sockset->num) {
                sockidx = 0;
            }

            if (NULL == p_cptr) {
                p_cptr = p_ds->p_head;
            }

            uint32_t dlen = build_local_lookup(p_cptr->p_str,packet,sizeof(packet));

            if (dlen) {
                ok = pktudp(sockfd,daddr,dport,packet,dlen);
            } else {
                ok = 0; // failed to create packet
            }

            uipost(p_ds->p_common->qid,E_MDNS,ok);

            p_cptr = p_cptr->p_next;

            // count completed iterations of local list:
            if (NULL == p_cptr) {
                uipost(p_ds->p_common->qid,E_MDNS_ITERATION,0);
            }

            // Wait for configured delay between operations:
            if (p_ds->p_common->delay_mdns) {
                local_terminate = mswait(p_ds->p_common->delay_mdns);
            }
        }
    }

    pthread_exit(p_priv);
}

//=============================================================================
// EOF loop_mdns.c
