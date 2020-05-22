// loop_dhcp.c
//=============================================================================

#include "cnetgen.h"

//-----------------------------------------------------------------------------

extern int dhcp_setup(internal_t *p_dhcp,dhcppriv_t *p_exported);
extern void dhcp_shutdown(internal_t *p_dhcp);
extern int dhcp_client(internal_t *p_dhcp);
extern int dhcp_process(internal_t *p_dhcp);

//-----------------------------------------------------------------------------

void *thread_dhcp(void *p_priv)
{
    dataset_t *p_ds = (dataset_t *)p_priv;
    common_t *p_common = p_ds->p_common;
    internal_t *p_dhcp = calloc(1,sizeof(internal_t *));

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);

    if (p_dhcp) {
        int local_terminate = 0;

        p_dhcp->p_common = p_common;
        p_dhcp->p_ctx = NULL;

        /* We execute this single libpcap DHCP thread but allow for
           p_common->clients_dhcp number of in-flight DHCP requests. This is
           instead of trying to manage the pcap interface across multiple
           threads (which would be a local resource issue). */

        local_terminate = dhcp_setup(p_dhcp,(dhcppriv_t *)p_ds->u.p_private);

        {
            msgdhcp_t msg;

            /* Wait for D_READY indicating listener loop is running, so that we
               do not miss packets during startup. */
            do {
                if (msgrcv(p_common->qid_dhcp,(void *)&msg,sizeof(msg.u),0,(MSG_NOERROR)) == -1) {
                    if (errno != ENOMSG) {
                        local_terminate = -1;
                    }
                } else {
                    if (D_READY == msg.mtype) {
                        break;
                    }
                }
            } while (0 == local_terminate);
        }

        while (0 == local_terminate) {
            int do_delta = -1;
            struct timespec istart; // iteration start time

            if (0 != clock_gettime(CLOCK_MONOTONIC_RAW,&istart)) {
                do_delta = 0;
            }

            (void)dhcp_client(p_dhcp);

            /* Above dhcp_client() call will generate the --dhcp-clients # of
               DISCOVERY operations across all the specified interfaces. e.g. If
               there are 4 supplied interfaces and --dhcp-clients 4 then we will
               expect to see 16 DISCOVERY requests per test iteration. Obviously
               the DHCP server free pool must be large enough, or some of the
               requests will fail. */
            local_terminate = dhcp_process(p_dhcp);

            // Wait for configured delay between operations (factoring in processing time):
            if ((0 == local_terminate) && p_dhcp->p_common->delay_dhcp) {
                uint32_t remaining = p_dhcp->p_common->delay_dhcp;
                if (do_delta) {
                    struct timespec iend;
                    if (0 == clock_gettime(CLOCK_MONOTONIC_RAW,&iend)) {
                        uint64_t tstart = AS_NANOSECONDS(&istart);
                        uint64_t tend = AS_NANOSECONDS(&iend);
                        uint32_t delta = (uint32_t)((tend - tstart) / (1000 * 1000));

                        //printf("DHCP iteration took %ums\n",delta);

                        if (delta < remaining) {
                            remaining -= delta;
                        }
                    }
                }
                local_terminate = mswait(remaining);
            }
        }

        dhcp_shutdown(p_dhcp);

        if (p_dhcp->p_ctx) {
            (void)free(p_dhcp->p_ctx);
        }
    }

    pthread_exit(p_priv);
}

//=============================================================================
// EOF loop_dhcp.c
