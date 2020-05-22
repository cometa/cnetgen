// loop_http.c
//=============================================================================

#include <curl/curl.h>

#include <malloc.h>

#include "cnetgen.h"

// TODO:IMPLEMENT: Allow user-agent to be overridden from the command-line:
//#define DEFAULT_USER_AGENT "libcurl-speedchecker/1.0"
#define DEFAULT_USER_AGENT "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"

//-----------------------------------------------------------------------------

/* CONSIDER: Implementing a callback that would validate the data returned to
   allow a known set of URLs to be checked; e.g. to verify correct interception
   by Cujo safebro. */

static size_t cb_sink_write(void *ptr __attribute((unused)),size_t size,size_t nmemb,void *data __attribute((unused)))
{
    // we are not interested in the data itself
    return (size * nmemb);
}

//-----------------------------------------------------------------------------

/* This code will see ALL the headers in a transaction. So if there is a
   redirect we will see:
      HTTP/1.1 301 Moved Permanently
   as well as the final:
      HTTP/1.1 200 OK
*/

//#define __HDRDEBUG (1) // do not enable by default (debugging aid)

typedef struct hcb {
    strlist_t *p_entry; // pointer to URL entry being tested
    // TODO:IMPLEMENT: Any per-call state that we need to track header information across calls
    // e.g. We may need to track if specific header values are seen when processing the URL
} hcb_t;

static size_t cb_header(char *p_buffer,size_t size,size_t nitems,void *p_data)
{
#if defined(__HDRDEBUG)
    hcb_t *p_ctx = p_data;

    {
        char header[nitems + 1]; // we cannot assume p_buffer is NUL terminated
        char *p_eol;
        memcpy(header,p_buffer,nitems);
        header[nitems] = '\0';
        if (NULL != (p_eol = strchr(header,'\r'))) {
            *p_eol = '\0';
        }
        if (NULL != (p_eol = strchr(header,'\n'))) {
            *p_eol = '\0';
        }
        printf("p_ctx %p nitems %3u size %3u : %s\n",p_ctx,(unsigned int)nitems,(unsigned int)size,header);
    }
#endif // __HDRDEBUG
    return (size * nitems);
}

//-----------------------------------------------------------------------------

static void stats_update_dbl(statistics_dbl_t *p_stats,double amount)
{
    if (p_stats->count < UINT_MAX) {
        p_stats->count++;
        if (amount) {
            p_stats->total += amount;
            if (amount < p_stats->min) {
                p_stats->min = amount;
            }
            if (p_stats->max < amount) {
                p_stats->max = amount;
            }
        }
    }

    return;
}

//-----------------------------------------------------------------------------

static int url_get(common_t *p_common,strlist_t *p_entry,const char *p_iface)
{
    int terminate = 0; // do not terminate ourselves by default

    if (p_common && p_entry && p_entry->p_str) {
        int ok = 0; // default reports as fail
        CURL *p_curl;
        CURLcode res;

        p_curl = curl_easy_init();
        if (p_curl) {
            char errbuf[CURL_ERROR_SIZE + 512]; // extra space for safety
            hcb_t hctx; // per-call header context

            // URL:
            curl_easy_setopt(p_curl,CURLOPT_URL,p_entry->p_str);

            // INTERFACE
            if (p_iface) {
                char tstr[3 + strlen(p_iface) + 1];
                (void)snprintf(tstr,sizeof(tstr),"if!%s",p_iface);
                curl_easy_setopt(p_curl,CURLOPT_INTERFACE,tstr);
            }

            // follow redirects:
            curl_easy_setopt(p_curl,CURLOPT_FOLLOWLOCATION,1L);
            // send all data to this function:
            curl_easy_setopt(p_curl,CURLOPT_WRITEFUNCTION,cb_sink_write);
            // set user-agent:
            curl_easy_setopt(p_curl,CURLOPT_USERAGENT,DEFAULT_USER_AGENT);
#if 0
            // SSL skip peer verification:
            curl_easy_setopt(p_curl,CURLOPT_SSL_VERIFYPEER,0L);
            // SSL skip hostname verification:
            curl_easy_setopt(p_curl,CURLOPT_SSL_VERIFYHOST,0L);

            //curl_easy_setopt(p_curl,CURLOPT_SSLVERSION,CURL_SSLVERSION_SSLv3);
#endif // boolean

#if 0
            // fail on 4xx errors:
            curl_easy_setopt(p_curl,CURLOPT_FAILONERROR,1L);
#endif // boolean

            // disable signals before setting timeout:
            curl_easy_setopt(p_curl,CURLOPT_NOSIGNAL,1L);
            // force timeout limit:
            curl_easy_setopt(p_curl,CURLOPT_TIMEOUT_MS,p_common->timeout_http);

            /* What are developers thinking when they allow unbounded buffers to
               be passed that are the destinations for writes. */
            // provide buffer for error reports:
            curl_easy_setopt(p_curl,CURLOPT_ERRORBUFFER,errbuf);
            errbuf[0] = '\0';

            /* The "p_entry->test" field is an enum: UT_DEFAULT, UT_SAFE, UT_UNSAFE
               We should report PASS/FAIL accordingly
               - UT_DEFAULT: as-is; just wether we get an OK response from the server
               - UT_SAFE: PASS when OK, FAIL for all other responses
               - UT_UNSAFE: PASS when blocked; FAIL if we get OK from original server
            */
            if ((UT_SAFE == p_entry->test) || (UT_UNSAFE == p_entry->test)) {
                // Set private data:
                hctx.p_entry = p_entry;
                curl_easy_setopt(p_curl,CURLOPT_HEADERDATA,&hctx);
                // Capture headers:
                curl_easy_setopt(p_curl,CURLOPT_HEADERFUNCTION,cb_header);
            }

            printpost(p_common->qid,E_HTTP_URL,"%s",p_entry->p_str);

            res = curl_easy_perform(p_curl);
            if (CURLE_OK == res) {
                double downloaded;
                double time_total;
                double time_dns;
                double time_connect;

                /* TODO:CONSIDER: When checking UT_SAFE/UT_UNSAFE we could use a
                   hardwired expected IP address for the block-page server *IF*
                   the Cujo does not hide that information. It depends how the
                   block-page is implemented.

                   Do we get a standard response (e.g. 503) or some non-standard
                   response (e.g. 450).

                   We may need to check some of the other information available
                   in the response to detect a block-page return. It may be
                   acceptable for testing to use such a hardwired IP address
                   (but if the tool was ever to become a generic tool then it
                   would not be an acceptable approach). */
                // CURLINFO_EFFECTIVE_URL    // when CURLOPT_FOLLOWLOCATION set this will return last effective URL
                // CURLINFO_HTTP_CONNECTCODE // returns long value for proxy return code (or 0 if no response available)
                // CURLINFO_HTTP_VERSION     // 0 if unknown otherwise CURL_HTTP_VERSION_1_0, CURL_HTTP_VERSION_1_1, or CURL_HTTP_VERSION_2_0
                // CURLINFO_REDIRECT_URL     // The URL a redirect WOULD take us to if CURLOPT_FOLLOWLOCATION was set
                // CURLINFO_CONTENT_TYPE     // NULL if invalid or missing "Content-Type:" header, otherwise the mime type returned
                // CURLINFO_PRIMARY_IP       // IP address of most recent connection done with the passed URL
                // CURLINFO_PRIMARY_PORT     // Port of most recent connection done with the passed URL
                switch (p_entry->test) {
                case UT_SAFE:
                case UT_UNSAFE:
                    {
                        long response_code;

                        if (CURLE_OK != (res = curl_easy_getinfo(p_curl,CURLINFO_RESPONSE_CODE,&response_code))) {
                            response_code = 0;
                        }
#if defined(__HDRDEBUG)
                        printf("DBG: %sSAFE response_code %u\n",((p_entry->test == UT_UNSAFE) ? "UN" : ""),(unsigned int)response_code);
#endif // __HDRDEBUG
                    }
                    break;

                case UT_DEFAULT:
                    // do nothing // we do not care about the result code only the statistics
                    break;

                default:
                    fprintf(stderr,"Internal ERROR - unrecognised URL test type %d\n",p_entry->test);
                    terminate = -1;
                    break;
                }

                // bytes:
                if (CURLE_OK != (res = curl_easy_getinfo(p_curl,CURLINFO_SIZE_DOWNLOAD,&downloaded))) {
                    downloaded = 0;
                }
                // seconds:
                if (CURLE_OK != (res = curl_easy_getinfo(p_curl,CURLINFO_TOTAL_TIME,&time_total))) {
                    time_total = 0;
                }
                // seconds:
                if (CURLE_OK != (res = curl_easy_getinfo(p_curl,CURLINFO_NAMELOOKUP_TIME,&time_dns))) {
                    time_dns = 0;
                }
                // seconds:
                if (CURLE_OK != (res = curl_easy_getinfo(p_curl,CURLINFO_CONNECT_TIME,&time_connect))) {
                    time_connect = 0;
                }

                // CONSIDER: CURLINFO_SPEED_DOWNLOAD for kbyte/sec download rate

                (void)pthread_mutex_lock(&p_entry->mutex);
                {
                    stats_update_uint(&p_entry->stats_amount,(uint32_t)downloaded);
                    stats_update_dbl(&p_entry->stats_time_total,time_total);
                    stats_update_dbl(&p_entry->stats_time_dns,time_dns);
                    stats_update_dbl(&p_entry->stats_time_connect,time_connect);
                }
                (void)pthread_mutex_unlock(&p_entry->mutex);

                ok = -1; // pass
            } else {
                printpost(p_common->qid,E_HTTP_URLLE,"%s: %s",p_entry->p_str,curl_easy_strerror(res));
            }

            curl_easy_cleanup(p_curl);
        } else {
            fprintf(stderr,"Complete curl failure - terminating\n");
            terminate = -1;
        }

        uipost(p_common->qid,E_HTTP,ok);
    } else {
        fprintf(stderr,"FATAL: Missing parameter data\n");
        terminate = -1;
    }

    return terminate;
}

//-----------------------------------------------------------------------------

void *thread_http(void *p_priv)
{
    dataset_t *p_ds = (dataset_t *)p_priv;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);

    if (p_ds) {
        int local_terminate = 0;
        strlist_t *p_cptr = NULL;
        strlist_t *p_initial = NULL;
        common_t *p_common = p_ds->p_common;
        interface_t *p_ciface = NULL;

        if (p_common) {
            p_ciface = p_common->p_interfaces;
        }

        /* This is a simplistic (non-optimal) approach to having each thread
           start at a different point in the supplied URL list. The hit is
           accepted since we only perform this once-per-thread at startup. */
        unsigned int starting_index = (pthread_prbs15() % p_ds->entries);
        if (starting_index) {
            unsigned int idx;

            p_initial = p_ds->p_head;
            for (idx = 0; ((idx < starting_index) && p_initial); idx++) {
                p_initial = p_initial->p_next;
            }
            p_cptr = p_initial;
        }

        while (0 == local_terminate) {
            if (NULL == p_cptr) {
                p_cptr = p_ds->p_head;
            }

            // Fetch from URL:
            local_terminate = url_get(p_common,p_cptr,(p_ciface ? p_ciface->p_iface : NULL));
            if (0 == local_terminate) {
                p_cptr = p_cptr->p_next;

                if (p_ciface) {
                    p_ciface = p_ciface->p_next;
                    if (NULL == p_ciface) {
                        p_ciface = p_common->p_interfaces;
                    }
                }

                // count completed iterations of URL list:
                if (p_initial == p_cptr) {
                    uipost(p_ds->p_common->qid,E_HTTP_ITERATION,0);
                }

                // Wait for configured delay between operations:
                if (p_ds->p_common->delay_http) {
                    local_terminate = mswait(p_ds->p_common->delay_http);
                }
            }
        }
    }

    pthread_exit(p_priv);
}

//=============================================================================
// loop_http.c
