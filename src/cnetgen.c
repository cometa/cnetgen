// cnetgen.c
//=============================================================================
/* Simple traffic generator

*/
//=============================================================================

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <getopt.h>
#include <time.h>
#include <curses.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <curl/curl.h>

#include "cnetgen.h"

//------------------------------------------------------------------------------

#define STRINGIFY(_x) STRINGIFY2(_x)
#define STRINGIFY2(_x) #_x

//-----------------------------------------------------------------------------

#define DEFAULT_HWIFACE "eth0"

#define DEFAULT_DELAY (1000) // milliseconds
#define DEFAULT_DELAY_DHCP (10 * 1000) // milliseconds
#define MIN_DELAY (0) // milliseconds
#define MAX_DELAY (60 * 1000) // milliseconds
#define MAX_DELAY_DHCP (8 * 60 * 60 * 1000) // milliseconds
#define DEFAULT_TIMEOUT_HTTP (2 * 60 * 1000) // milliseconds
#define DEFAULT_TIMEOUT_MDNS (20 * 1000) // milliseconds
#define DEFAULT_TIMEOUT_DHCP (20 * 1000) // milliseconds
#define MAX_TIMEOUT (5 * 60 * 1000) // milliseconds
#define DEFAULT_STAGGER (0) // milliseconds
#define MAX_STAGGER (500) // milliseconds

// The following should not be increased due to dhcp-client.c expectations:
#define MAX_DHCP_COUNT (255) // simulated interfaces

//-----------------------------------------------------------------------------

// Clunky, but simple, asynchronous notification to main control UI loop:
static volatile int terminate_loop = 0;

//-----------------------------------------------------------------------------
/**
 * Wrapper for formatted syslog output.
 *
 * @param priority Standard syslog priority (e.g. LOG_INFO, LOG_ERR, etc.)
 * @param fmt Standard NUL terminated printf-style format string.
 * @param ... Parameters as required for the fmt string.
 */
void log_printf(int priority,const char *fmt,...)
{
    va_list ap;
    va_start(ap,fmt);
    vsyslog(priority,fmt,ap);
    va_end(ap);
    return;
}

//-----------------------------------------------------------------------------
/**
 * Pseudo Random Bit Sequence (PRBS) generator. This "randomness" is NOT being
 * used for security/cryptographic purposes so repeatability is not an issue. We
 * just need to provide an even spread of values. Repeatability is useful for
 * testing. The algorithm is chosen for having a low run-time cost.
 *
 * @return Unsigned 15-bit value.
 */

static uint16_t prbs15(void)
{
    static uint16_t lfsr = 0x0002; // must be (any) non-zero value
    lfsr = ((lfsr << 1) | (((lfsr >> 14) ^ (lfsr >> 13)) & 1));
    return (lfsr & ((1 << 15) - 1));
}

//-----------------------------------------------------------------------------

uint16_t pthread_prbs15(void)
{
    static pthread_mutex_t mutex_prbs = PTHREAD_MUTEX_INITIALIZER;
    uint16_t val;
    pthread_mutex_lock(&mutex_prbs);
    {
        val = prbs15();
    }
    pthread_mutex_unlock(&mutex_prbs);
    return val;
}

//-----------------------------------------------------------------------------

int mswait(uint32_t msecs)
{
    int do_terminate = 0;
    struct timespec req;
    struct timespec rem;

    req.tv_sec = (msecs / 1000); // seconds
    req.tv_nsec = ((msecs % 1000) * 1000 * 1000); // ms to ns

    while (clock_nanosleep(CLOCK_REALTIME,0,&req,&rem)) {
        if (EINTR == errno) {
            req = rem;
        } else {
            do_terminate = -1;
            break;
        }
    }

    return do_terminate;
}

//-----------------------------------------------------------------------------

void stats_update_uint(statistics_uint_t *p_stats,uint32_t amount)
{
    if (p_stats->count < UINT_MAX) {
        p_stats->count++;
        if (amount) {
            p_stats->total += (uint64_t)amount;
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

void postmsg(int qid,void *p_msg,size_t msgsz)
{
    uint32_t retries = 10;

    // blocking send
    while (retries) {
        if (msgsnd(qid,p_msg,msgsz,0) == -1) {
            /* EINTR: Sleeping on a full message queue condition, the process
               caught a signal. We try again (upto retries count). */
            if (EINTR != errno) {
                /* This really is FATAL, and is the delivery mechanism for
                   E_FATAL so we need to do something else. */

                // EACCES The calling process does not have write permission on the message queue, and does not have the CAP_IPC_OWNER capability.
                // EAGAIN The message cannot be sent due to the msg_qbytes limit for the queue and IPC_NOWAIT was specified in msgflg (should not see this since using blocking posts)
                // EFAULT The address pointed to by msgp is not accessible.
                // EIDRM  The message queue was removed.
                // EINVAL Invalid msqid value, or nonpositive mtype value, or invalid msgsz value (less than 0 or greater than the system value MSGMAX).
                // ENOMEM The system does not have enough memory to make a copy of the message pointed to by msgp.

                perror("msgsnd error");
                exit(EXIT_FAILURE);
            }
        } else  {
            break;
        }

        retries--;
    }

    return;
}

//-----------------------------------------------------------------------------

void vprintpost(int qid,worker_e type,const char *p_format,va_list ap)
{
    msgui_t msg;

    (void)memset(&msg,'\0',sizeof(msg)); // for valgrind

    msg.mtype = type;

    vsnprintf(msg.u.txt,sizeof(msg.u.txt),p_format,ap);

    postmsg(qid,&msg,sizeof(msg.u));
    return;
}

void printpost(int qid,worker_e type,const char *p_format,...)
{
    va_list ap;
    va_start(ap,p_format);
    vprintpost(qid,type,p_format,ap);
    va_end(ap);
    return;
}

//-----------------------------------------------------------------------------

void uipost(int qid,worker_e type,int ok)
{
    msgui_t msg;

    (void)memset(&msg,'\0',sizeof(msg)); // for valgrind

    msg.mtype = type;
    msg.u.pass = ok;

    postmsg(qid,&msg,sizeof(msg.u));
    return;
}

//-----------------------------------------------------------------------------
/**
 * Take a copy of a string, allocating a new buffer to hold the NUL-terminated
 * result.
 *
 * @param p_src Pointer to NUL terminated source string.
 * @param amount If non-zero the number of characters to copy into the new string, otherwise copy the whole string.
 * @return Pointer to NUL terminated copy of passed string.
 */
static char *copystring(const char *p_src,size_t amount)
{
    char *p_newstring;

    if (amount == 0) {
        amount = strlen(p_src);
    }
    amount += 1; // for terminating NUL

    // We use calloc to pre-zero so we KNOW that we have a terminating NUL
    if (NULL != (p_newstring = calloc(1,amount))) {
        strncpy(p_newstring,p_src,(amount - 1));
    } else {
        fprintf(stderr,"Failed to allocate for copystring: returning NULL\n");
        // our callers can handle NULL result so do not terminate here
    }

    return p_newstring;
}

//-----------------------------------------------------------------------------
/**
 * Check a referenced string is a valid base10 number within the range
 * specified. On error the function will exit() so should only be called from
 * command-line argument processing.
 *
 * @param p_tag Pointer to NUL terminated string descriptor for value being parsed.
 * @param p_str Pointer to NUL terminated base10 number string.
 * @param min Minimum acceptable value.
 * @param max Maximum acceptable value.
 * @return A number within the min->max range.
 */
static uint32_t arg_val(const char *p_tag,char *p_str,uint32_t min,uint32_t max)
{
    unsigned int aval = 0;
    char *p_end = NULL;
    unsigned long ltmp = strtoul(p_str,&p_end,10);

    if ((p_end == p_str) || (NULL == p_end) || (*p_end)) {
        fprintf(stderr,"Supplied value \"%s\" for \"%s\" is not a valid number\n",p_str,p_tag);
        exit(EXIT_FAILURE);
    } else if ((ltmp < min) || (ltmp > max) || (ltmp == ULONG_MAX)) {
        fprintf(stderr,"Supplied value %u  for \"%s\" is invalid (min %u max %u)\n",(unsigned int)ltmp,p_tag,min,max);
        exit(EXIT_FAILURE);
    } else {
        aval = (uint32_t)ltmp;
    }

    return aval;
}

//-----------------------------------------------------------------------------
//-- ncurses ------------------------------------------------------------------
//-----------------------------------------------------------------------------

#define HRED     (1)
#define HGREEN   (2)
#define HYELLOW  (3)
#define HMAGENTA (4)
#define HCYAN    (5)
#define BCYAN    (6)
#define BBLUE    (7)
#define BRED     (8)

#define COLOUR_ON(n)                    \
    do {                                \
        if (((n) >= 1) && ((n) <= 8)) { \
            if (do_colour) {            \
                attron(COLOR_PAIR(n));  \
            }                           \
        }                               \
    } while (0)

#define COLOUR_OFF(n)                   \
    do {                                \
        if (((n) >= 1) && ((n) <= 8)) { \
            if (do_colour) {            \
                attroff(COLOR_PAIR(n)); \
            }                           \
        }                               \
    } while (0)

//-----------------------------------------------------------------------------

typedef enum {
    NOP = 0, // not normally used
    JOIN,
    CANCEL
} threadop_e;

static void do_threadop(pthread_t *p_vec,uint32_t count,threadop_e op)
{
    if (p_vec) {
        unsigned int idx;
        for (idx = 0; (idx < count); idx++) {
            void *status = NULL;
            int error;
            switch (op) {
            case JOIN:
                error = pthread_join(p_vec[idx],&status);
                break;
            case CANCEL:
                error = pthread_cancel(p_vec[idx]);
                break;
            case NOP:
                error = 0;
                break;
            default:
                fprintf(stderr,"Unrecognised thread operation %d\n",op);
                error = ENOENT;
                break;
            }
            if (error) {
                if (error != ESRCH) {
                    fprintf(stderr,"Error %d \"%s\" from thread vector %p idx %u\n",error,strerror(error),p_vec,idx);
                }
            } else {
                if (JOIN == op) {
                    fprintf(stderr,"Completed thread with status %p for vector %p idx %u\n",status,p_vec,idx);
                }
            }
        }
    }

    return;
}

//-----------------------------------------------------------------------------

static void *loop_control(void *p_priv)
{
    char *p_fatal = NULL;
    common_t *p_common = (common_t *)p_priv;
    WINDOW *p_top = NULL;
    int do_colour = 0;
    int row;
    int col;

    if (p_common->silent) {
        printf("Starting in silent mode. Use Ctrl-C to terminate\n");
    }

    if (p_common->ncurses) {
        if (NULL == (p_top = initscr())) {
            fprintf(stderr,"Failed to initialise ncurses\n");
            p_common->terminate = -1;
        } else {
            getmaxyx(p_top,row,col);

            if (col < 80) {
                fprintf(stderr,"Too few columns (at least 80 required)\n");
                p_common->terminate = -1;
            }

            if (row < 20) {
                fprintf(stderr,"Too few rows (at least 20 required)\n");
                p_common->terminate = -1;
            }

            if (0 == p_common->terminate) {
                do_colour = (TRUE == has_colors());
                if (do_colour) {
                    start_color();

                    if (COLOR_PAIRS <= 8) {
                        fprintf(stderr,"Not enough COLOR_PAIRS %u, needed 8. Disabling colour support.\n",COLOR_PAIRS);
                        do_colour = 0;
                    } else {
                        init_pair( 1,COLOR_RED,    COLOR_BLACK);
                        init_pair( 2,COLOR_GREEN,  COLOR_BLACK);
                        init_pair( 3,COLOR_YELLOW, COLOR_BLACK);
                        init_pair( 4,COLOR_MAGENTA,COLOR_BLACK);
                        init_pair( 5,COLOR_CYAN,   COLOR_BLACK);
                        init_pair( 6,COLOR_BLACK,  COLOR_CYAN);
                        init_pair( 7,COLOR_WHITE,  COLOR_BLUE);
                        init_pair( 8,COLOR_WHITE,  COLOR_RED);
                    }
                }

                wattron(p_top,COLOR_BLACK);

                curs_set(0);
                clear();

                COLOUR_ON(HYELLOW);
                mvwprintw(p_top,0,0,"cnetgen");
                COLOUR_OFF(HYELLOW);
                mvwprintw(p_top,0,10,"(Ctrl-C to quit)");

                //                             1         2         3         4         5         6         7
                //                   01234567890123456789012345678901234567890123456789012345678901234567890123456789
                mvwprintw(p_top,2,0,"task   #-threads  iterations   completed      errors");
                // iterations is number of times a thread has completed (so the sum of all loop completions)
                // completed is total number of operations performed across all threads
                // errors is total number of errors that were caught (e.g. timeout, non-OK HTTP, FQDN not found, whatever)

                // maybe underneath we should have a line for each thread (optional) that shows current operation and information about it
                // - or alternatively have a logfile created with performance information - that can be dumped at the end
                // - - so track size information and timing for each URL and provide min/avg/max information as appropriate for the time the test was running

                COLOUR_ON(HGREEN);
                mvwprintw(p_top,3,0,"HTTP");
                mvwprintw(p_top,4,0,"mDNS");
                mvwprintw(p_top,5,0,"DHCP");
                COLOUR_OFF(HGREEN);
                COLOUR_ON(HYELLOW);
                mvwprintw(p_top,10,0,"URL:");
                mvwprintw(p_top,14,0,"DHCP:");
#if defined(__DHCPSTATS_RUNNING)
                mvwprintw(p_top,15,0,"DHCP-stats:");
#endif // __DHCPSTATS_RUNNING
                COLOUR_OFF(HYELLOW);
                mvwprintw(p_top,12,0,"LastErr:");

                mvwprintw(p_top,3,12,"%u",p_common->clients_http);
                mvwprintw(p_top,4,12,"%u",p_common->clients_mdns);
                mvwprintw(p_top,5,12,"%u",p_common->clients_dhcp);

                refresh();
            }
        }
    }

    while ((0 == terminate_loop) && (0 == p_common->terminate)) {
        struct msgui msg;

        if (msgrcv(p_common->qid,(void *)&msg,sizeof(msg.u),0,(MSG_NOERROR)) == -1) {
            // ENOMSG IPC_NOWAIT was specified in msgflg and no message of the requested type existed on the message queue.
            // ENOMSG IPC_NOWAIT and MSG_COPY were specified in msgflg and the queue contains less than msgtyp messages.
            if (errno != ENOMSG) {
                // E2BIG  The message text length is greater than msgsz and MSG_NOERROR isn't specified in msgflg.
                // EACCES The calling process does not have read permission on the message queue, and does not have the CAP_IPC_OWNER capability.
                // EFAULT The address pointed to by msgp isn't accessible.
                // EIDRM  While the process was sleeping to receive a message, the message queue was removed.
                // EINTR  While the process was sleeping to receive a message, the process caught a signal; see signal(7).
                // EINVAL msgqid was invalid, or msgsz was less than 0.
                // EINVAL (since Linux 3.14) msgflg specified MSG_COPY, but not IPC_NOWAIT.
                // EINVAL (since Linux 3.14) msgflg specified both MSG_COPY and MSG_EXCEPT.
                // ENOSYS (since Linux 3.8) MSG_COPY was specified in msgflg, and this kernel was configured without CONFIG_CHECKPOINT_RESTORE.
                perror("msgrcv");
                p_common->terminate = -1;
            }
            if (0 == p_common->silent) {
                fprintf(stderr,"No message available for msgrcv()\n");
            }
        } else {
            switch (msg.mtype) {
            case E_HTTP:
                if (msg.u.pass && (p_common->http_pass < UINT_MAX)) {
                    p_common->http_pass++;
                } else if (p_common->http_fail < UINT_MAX) {
                    p_common->http_fail++;
                }
                if (p_common->ncurses) {
                    if (msg.u.pass) {
                        mvwprintw(p_top,3,30,"%10u",p_common->http_pass);
                    } else {
                        COLOUR_ON(HYELLOW);
                        mvwprintw(p_top,3,42,"%10u",p_common->http_fail);
                        COLOUR_OFF(HYELLOW);
                    }
                } else {
                    if (0 == p_common->silent) {
                        printf("test result: HTTP: type %ld %s\n",msg.mtype,(msg.u.pass ? "PASS" : "FAIL"));
                    }
                }
                break;
            case E_MDNS:
                if (msg.u.pass && (p_common->mdns_pass < UINT_MAX)) {
                    p_common->mdns_pass++;
                } else if (p_common->mdns_fail < UINT_MAX) {
                    p_common->mdns_fail++;
                }
                if (p_common->ncurses) {
                    if (msg.u.pass) {
                        mvwprintw(p_top,4,30,"%10u",p_common->mdns_pass);
                    } else {
                        COLOUR_ON(HYELLOW);
                        mvwprintw(p_top,4,42,"%10u",p_common->mdns_fail);
                        COLOUR_OFF(HYELLOW);
                    }
                } else {
                    if (0 == p_common->silent) {
                        printf("test result: mDNS: type %ld %s\n",msg.mtype,(msg.u.pass ? "PASS" : "FAIL"));
                    }
                }
                break;
            case E_DHCP:
                if (msg.u.pass && (p_common->dhcp_pass < UINT_MAX)) {
                    p_common->dhcp_pass++;
                } else if (p_common->dhcp_fail < UINT_MAX) {
                    p_common->dhcp_fail++;
                }
                if (p_common->ncurses) {
                    if (msg.u.pass) {
                        mvwprintw(p_top,5,30,"%10u",p_common->dhcp_pass);
                    } else {
                        COLOUR_ON(HYELLOW);
                        mvwprintw(p_top,5,42,"%10u",p_common->dhcp_fail);
                        COLOUR_OFF(HYELLOW);
                    }
                } else {
                    if (0 == p_common->silent) {
                        printf("test result: DHCP: type %ld %s\n",msg.mtype,(msg.u.pass ? "PASS" : "FAIL"));
                    }
                }
                break;

            case E_HTTP_URL:
                if (p_common->ncurses) {
                    mvwprintw(p_top,10,6,msg.u.url);
                    clrtoeol();
                } else {
                    if (0 == p_common->silent) {
                        printf("test URL \"%s\"\n",msg.u.url);
                    }
                }
                break;

            case E_HTTP_URLLE:
                if (p_common->ncurses) {
                    COLOUR_ON(BRED);
                    mvwprintw(p_top,12,10,msg.u.url);
                    COLOUR_OFF(BRED);
                    clrtoeol();
                } else {
                    if (0 == p_common->silent) {
                        printf("last error \"%s\"\n",msg.u.url);
                    }
                }
                break;

            case E_HTTP_ITERATION:
                if (p_common->http_iters < UINT_MAX) {
                    p_common->http_iters++;
                }
                if (p_common->ncurses) {
                    mvwprintw(p_top,3,18,"%10u",p_common->http_iters);
                } else {
                    if (0 == p_common->silent) {
                        printf("Starting HTTP iteration\n");
                    }
                }
                break;

            case E_MDNS_ITERATION:
                if (p_common->mdns_iters < UINT_MAX) {
                    p_common->mdns_iters++;
                }
                if (p_common->ncurses) {
                    mvwprintw(p_top,4,18,"%10u",p_common->mdns_iters);
                } else {
                    if (0 == p_common->silent) {
                        printf("Starting HTTP iteration\n");
                    }
                }
                break;

            case E_DHCP_TXT:
                if (p_common->ncurses) {
                    mvwprintw(p_top,14,6,msg.u.txt);
                    clrtoeol();
                } else {
                    if (0 == p_common->silent) {
                        printf("DHCP: %s\n",msg.u.txt);
                    }
                }
                break;

            case E_DHCP_STATS:
                if (p_common->ncurses) {
                    mvwprintw(p_top,15,12,msg.u.txt);
                    clrtoeol();
                } else {
                    if (0 == p_common->silent) {
                        printf("DHCP-stats: %s\n",msg.u.txt);
                    }
                }
                break;

            case E_FATAL:
                if (p_common->ncurses) {
                    COLOUR_ON(BRED);
                    mvwprintw(p_top,15,0,msg.u.err);
                    COLOUR_OFF(BRED);
                    clrtoeol();
                }
                p_fatal = copystring(msg.u.err,0);
                p_common->terminate = -1;
                break;

            default:
                if (0 == p_common->silent) {
                    fprintf(stderr,"Unrecognised type %ld\n",msg.mtype);
                }
                break;
            }
        }

        if (p_common->ncurses) {
            refresh();
        }
    }

    // Terminate all threads:
    if (p_common->clients_dhcp) {
        do_threadop(p_common->tid_dhcp,p_common->threads_dhcp,CANCEL);
        do_threadop(p_common->tid_dhcp,p_common->threads_dhcp,JOIN);
    }
    if (p_common->clients_mdns) {
        do_threadop(p_common->tid_mdns,p_common->clients_mdns,CANCEL);
        do_threadop(p_common->tid_mdns,p_common->clients_mdns,JOIN);
    }
    if (p_common->clients_http) {
        do_threadop(p_common->tid_http,p_common->clients_http,CANCEL);
        do_threadop(p_common->tid_http,p_common->clients_http,JOIN);
    }

    if (p_common->ncurses) {
        if (p_top) {
            curs_set(1);
            delwin(p_top);
            endwin();
            refresh();
        }
    }

    if (p_fatal) {
        fprintf(stderr,"FATAL: %s\n",p_fatal);
        (void)free(p_fatal);
    }

    pthread_exit(p_common);
}

//-----------------------------------------------------------------------------
//-- application control ------------------------------------------------------
//-----------------------------------------------------------------------------

static void signal_handler(int signum)
{
    //int ecode = EXIT_SUCCESS;
    int do_shutdown = -1;

    switch (signum) {
    case SIGHUP: // requested termination
        fprintf(stderr,"User requested termination\n");
        break;

    case SIGINT:
        fprintf(stderr,"Terminal requested termination\n");
        break;

    default:
        fprintf(stderr,"ERROR: Unexpected signal %d\n",signum);
        //ecode = EXIT_FAILURE;
        break;
    }

    if (do_shutdown) {
        extern void dhcp_listener_terminate(void);
        dhcp_listener_terminate();
        /* NOTE: Clean termination relies on well behaved threads that will
           periodically signal the UI. If a thread misbehaves then SIGKILL will
           be needed to force termination. */
        terminate_loop = -1;
    }

    return;
}

//-----------------------------------------------------------------------------

static void list_dump(strlist_t *p_list)
{
    strlist_t *p_cptr;

    printf("# HTTP performance:\n");
    printf("success_count,transfer_size_min,transfer_size_avg,transfer_size_max,time_transfer_min,time_transfer_avg,time_transfer_max,time_dns_min,time_dns_avg,time_dns_max,time_connect_min,time_connect_avg,time_connect_max,url\n");
    for (p_cptr = p_list; (p_cptr); p_cptr = p_cptr->p_next) {
        if (p_cptr->stats_amount.count) {
            printf("%u,%u,%u,%u",p_cptr->stats_amount.count,p_cptr->stats_amount.min,(uint32_t)(p_cptr->stats_amount.total / p_cptr->stats_amount.count),p_cptr->stats_amount.max);
        } else {
            printf("0,,,");
        }
        if (p_cptr->stats_time_total.count) {
            printf(",%0.3f,%0.3f,%0.3f",p_cptr->stats_time_total.min,(p_cptr->stats_time_total.total / p_cptr->stats_time_total.count),p_cptr->stats_time_total.max);
        } else {
            printf(",,,");
        }
        if (p_cptr->stats_time_dns.count) {
            printf(",%0.3f,%0.3f,%0.3f",p_cptr->stats_time_dns.min,(p_cptr->stats_time_dns.total / p_cptr->stats_time_dns.count),p_cptr->stats_time_dns.max);
        } else {
            printf(",,,");
        }
        if (p_cptr->stats_time_connect.count) {
            printf(",%0.3f,%0.3f,%0.3f",p_cptr->stats_time_connect.min,(p_cptr->stats_time_connect.total / p_cptr->stats_time_connect.count),p_cptr->stats_time_connect.max);
        } else {
            printf(",,,");
        }
        printf(",%s\n",p_cptr->p_str);
    }

    return;
}

//-----------------------------------------------------------------------------

static void list_free(strlist_t *p_list)
{
    strlist_t *p_cptr;

    for (p_cptr = p_list; (p_cptr);) {
        strlist_t *p_del = p_cptr;
        p_cptr = p_cptr->p_next;
        (void)free((char *)p_del->p_str);
        {
            int error = pthread_mutex_destroy(&p_del->mutex);
            if (error) {
                fprintf(stderr,"Error %d destroying mutex\n",error); // EBUSY, etc.
            }
        }
        (void)free(p_del);
    }

    return;
}

//-----------------------------------------------------------------------------
/**
 * Build list of one-per-line simple list file contents. We cache the data
 * internally to perform some initial validation, and to avoid re-reading the
 * same file contents over and over during testing loops. On error this function
 * will exit() so should only be called from command-line processing currently.
 *
 * @param p_filename Pointer to NUL terminated source filename.
 * @param utype Type of validation testing to be performed on the URLs
 * @param p_entries Optional pointer to field to be populated with number of descriptors in final list.
 * @return NULL terminated list of URL descriptors.
 */

static strlist_t *list_build(const char *p_filename,urltest_e utype,size_t *p_entries)
{
    strlist_t *p_list = NULL;
    FILE *p_fh = fopen(p_filename,"r");
    size_t entries = 0;

    if (p_fh) {
        if (fseek(p_fh,0,SEEK_END) == 0) {
            size_t length = (size_t)ftell(p_fh);

            if (length >= 0) {
                if (fseek(p_fh,0,SEEK_SET) == 0) {
                    strlist_t *p_head = NULL;
                    strlist_t *p_last = NULL;
                    char buffer[MAX_URL + 1];
                    char *p_line;

                    // read lines: creating list entries (in order lines appear so add to tail):
                    while (!feof(p_fh) && (NULL != (p_line = fgets(buffer,(int)sizeof(buffer),p_fh)))) {
                        size_t amount = strlen(p_line);
                        if (amount) {
                            if ('\n' == p_line[amount - 1]) {
                                amount--;
                            }
                            if (amount) {
                                strlist_t *p_new = calloc(1,sizeof(strlist_t));
                                if (p_new) {
                                    int error;

                                    error = pthread_mutex_init(&p_new->mutex,NULL);
                                    if (error) {
                                        fprintf(stderr,"Error %d initialising mutex for \"%s\"\n",error,p_line);
                                        exit(EXIT_FAILURE);
                                    }

                                    p_new->p_str = copystring(p_line,amount);
                                    p_new->test = utype;

                                    p_new->stats_amount.min = UINT_MAX;
                                    p_new->stats_time_total.min = DBL_MAX;
                                    p_new->stats_time_dns.min = DBL_MAX;
                                    p_new->stats_time_connect.min = DBL_MAX;


                                    if (p_last) {
                                        p_last->p_next = p_new;
                                    }
                                    if (NULL == p_head) {
                                        p_head = p_new;
                                    }
                                    p_last = p_new;

                                    entries++;
                                } else {
                                    perror("OOM");
                                    p_last = NULL; // use as indicator of failure
                                    break;
                                }
                            }
                        }
                    }

                    if (p_head && (NULL == p_last)) {
                        list_free(p_head);
                    } else {
                        p_list = p_head;
                        if (p_entries) {
                            *p_entries = entries;
                        }
                    }
                } else {
                    perror("Failed to go back to start of file");
                }
            } else {
                fprintf(stderr,"Invalid file length");
            }
        } else {
            perror("Failed to go to end of file");
        }

        (void)fclose(p_fh);
    } else {
        perror("Failed opening file");
    }

    return p_list;
}

//-----------------------------------------------------------------------------
/**
 * Since we have a single forward list, and we only need to perform these
 * operations during the start-of-day building the main list, we take the hit of
 * an iterative scan rather than the overhead of managing an active tail
 * pointer for easier list joining.
 *
 * @param p_list Pointer to NULL terminated list to scan.
 * @return Pointer to last entry in supplied list, or NULL if list was empty.
 */

static strlist_t *list_last(strlist_t *p_list)
{
    strlist_t *p_last = NULL;
    if (p_list) {
        p_last = p_list;
        while (p_last->p_next) {
            p_last = p_last->p_next;
        }
    }
    return p_last;
}

//-----------------------------------------------------------------------------

// ---------jk---o-----------
static const struct option opts[] = {
    {"help",no_argument,0,'h'},
    {"verbose",no_argument,0,'v'},
    {"silent",no_argument,0,'x'},
    {"http-clients",required_argument,0,'w'},
    {"http-list",required_argument,0,'u'},
    {"http-safe",required_argument,0,'g'},
    {"http-unsafe",required_argument,0,'f'},
    {"mdns-clients",required_argument,0,'m'},
    {"mdns-list",required_argument,0,'l'},
    {"dhcp-clients",required_argument,0,'d'},
    {"dhcp-iface",required_argument,0,'e'},
    {"dhcp-count",required_argument,0,'n'},
    {"interface",required_argument,0,'i'},
    {"ehw",required_argument,0,'e'},
    {"delay",required_argument,0,'y'},
    {"delay-http",required_argument,0,'a'},
    {"delay-mdns",required_argument,0,'b'},
    {"delay-dhcp",required_argument,0,'c'},
    {"timeout",required_argument,0,'t'},
    {"timeout-http",required_argument,0,'p'},
    {"timeout-mdns",required_argument,0,'q'},
    {"timeout-dhcp",required_argument,0,'r'},
    {"stagger",required_argument,0,'s'},
    {"disable-ncurses",no_argument,0,'z'},
    {NULL,0,0,0}
};

//-----------------------------------------------------------------------------

/* For backwards command-line compatibility we retain the --timeout and --delay
   options, but each worker type now has their own timeout control. */

static void command_line_help(const char *progname)
{
    fprintf(stderr,"%s [--help] [--verbose]\n",progname);
    fprintf(stderr,"Generate network load.\n");
    fprintf(stderr,"(Version " STRINGIFY(BUILDVERSION) " built " __DATE__ " " __TIME__ ") marker %u\n\n",BUILDTIMESTAMP);

    fprintf(stderr,"--interface/-i\t\tNetwork interface name(s) to use for transmissions.\n");
    fprintf(stderr,"--ehw/-e\t\tExplicit hardware interface name for DHCP testing (default " DEFAULT_HWIFACE ").\n");
    fprintf(stderr,"--http_clients/-w\tNumber of HTTP client threads to execute.\n");
    fprintf(stderr,"--http-list/-u\t\tFile containing list of URLs to resolve, with one-per-line.\n");
    fprintf(stderr,"--http-safe/-g\t\tFile containing list of known safe URLs to resolve (one-per-line).\n");
    fprintf(stderr,"--http-unsafe/-f\t\tFile containing list of known unsafe malicious URLs to resolve (one-per-line).\n");
    fprintf(stderr,"--mdns-clients/-m\tNumber of mDNS client threads to execute.\n");
    fprintf(stderr,"--mdns-list/-l\t\tFile containing list of .local hostnames to resolve, with one-per-line.\n");
    fprintf(stderr,"--dhcp-clients/-d\tNumber of DHCP client threads to execute.\n");
    fprintf(stderr,"--dhcp-count/-n\t\tNumber of DHCP interfaces to simulate (default is --interface count). Range 1..%u\n",MAX_DHCP_COUNT);
    fprintf(stderr,"--dhcp-iface/-e\t\tNetwork interface name to use for DHCP transmissions (option is synonym for --ehw).\n");

    fprintf(stderr,"--delay/-y\t\tMilliseconds delay between operations (default %ums). Range %u..%u\n",DEFAULT_DELAY,MIN_DELAY,MAX_DELAY);
    fprintf(stderr,"--timeout/-t\t\tMilliseconds for individual operation timeout (default %ums). Range 100..%u\n",DEFAULT_TIMEOUT_HTTP,MAX_TIMEOUT);
    fprintf(stderr,"--stagger/-s\t\tMilliseconds stagger when creating threads (default %ums). Range 0..%u\n",DEFAULT_STAGGER,MAX_STAGGER);

    fprintf(stderr,"--delay-http/-a\t\tMilliseconds delay between HTTP operations (default as --delay). Range %u..%u\n",MIN_DELAY,MAX_DELAY);
    fprintf(stderr,"--delay-mdns/-b\t\tMilliseconds delay between mDNS operations (default as --delay). Range %u..%u\n",MIN_DELAY,MAX_DELAY);
    fprintf(stderr,"--delay-dhcp/-c\t\tMilliseconds delay between DHCP operations (default %ums). Range %u..%u\n",DEFAULT_DELAY_DHCP,MIN_DELAY,MAX_DELAY_DHCP);

    fprintf(stderr,"--timeout-http/-p\tMilliseconds for individual HTTP operation timeout (default %ums). Range 100..%u\n",DEFAULT_TIMEOUT_HTTP,MAX_TIMEOUT);
    fprintf(stderr,"--timeout-mdns/-q\tMilliseconds for individual mDNS operation timeout (default %ums). Range 100..%u\n",DEFAULT_TIMEOUT_MDNS,MAX_TIMEOUT);
    fprintf(stderr,"--timeout-dhcp/-r\tMilliseconds for individual DHCP iteration timeout (default %ums). Range 100..%u\n",DEFAULT_TIMEOUT_DHCP,MAX_TIMEOUT);

    fprintf(stderr,"--disable-ncurses/-z\tDisable ncurses based \"UI\".\n");
    fprintf(stderr,"--silent/-x\t\tSilent mode (implies --disable-ncurses).\n");
    fprintf(stderr,"--help/-h\t\tDisplay this help information.\n");
    fprintf(stderr,"--verbose/-v\t\tIncrease logging verbosity.\n");

    fprintf(stderr,"\nNOTEs:\n");

    fprintf(stderr,"\nThe --interface option can accept a comma seperated list of network interface\n"
            "names if more than one interface should be used. For HTTP and mDNS worker\n"
            "requests the operations will loop around the set of specified interfaces.\n"
            "For DHCP workers, to avoid interfering with any active HTTP or mDNS connections,\n"
            "a seperate set of MAC addresses are used to request network addresses. This\n"
            "means that the test should be tuned for the DHCP free pool size in the test\n"
            "environment.\n");

    fprintf(stderr,"\nFor the number of --dhcp-clients workers specified the number of interfaces to\n"
            "simulate is supplied either by the explicit --dhcp-count option or (if it is not\n"
            "specified) the count of --interface supplied interfaces. The #clients and\n"
            "#interfaces values are used to define the total number of unique inflight DHCP\n"
            "requests tested (#clients * #interfaces). As mentioned above, the cnetgen code\n"
            "does not directly use the MAC addresses of the specified network interfaces. A\n"
            "fixed locally administered MAC range is used for DHCP testing.\n");

    fprintf(stderr,"\nThe --http-clients threads can accept URIs for \"http\", \"https\", \"ftp\",\n"
            "\"tftp\", and other protocols as supported by libcurl.\n");
    fprintf(stderr,"The --http-list supplied URLs are just fetched with no interpretation of the\n"
            "returned data performed. The --http-safe list is checked for valid 200 OK\n"
            "responses. The --http-unsafe list is checked for correct interception by the\n"
            "safe-browsing block-page.\n");

    fprintf(stderr,"\nThe --mdns-clients threads do A and AAAA queries on the supplied\n"
            "--mdns-list entries. Even though a --timeout-mdns option is available it is NOT\n"
            "currently used since the mDNS is a fire-and-forget test and does not currently\n"
            "perform validation.\n");

    return;
}

//-----------------------------------------------------------------------------

int main(int argc,char **argv)
{
    char *p_fnamelist_http = NULL;
    char *p_fnamelist_http_safe = NULL;
    char *p_fnamelist_http_unsafe = NULL;
    char *p_fnamelist_mdns = NULL;
    dataset_t data_http;
    dataset_t data_mdns;
    dataset_t data_dhcp;
    pthread_t tid_display;
    common_t common;
    dhcppriv_t dhcpinfo;

    // common control state:
    memset(&common,'\0',sizeof(common)); // zero all fields

    common.qid = msgget(ftok(argv[0],0x01),(IPC_CREAT | 0666));
    common.qid_dhcp = msgget(ftok(argv[0],0x02),(IPC_CREAT | 0666));

    common.ncurses = -1; // ncurses "UI" enabled by default
    common.delay_common = DEFAULT_DELAY;
    common.delay_http = 0xFFFFFFFF;
    common.delay_mdns = 0xFFFFFFFF;
    common.delay_dhcp = DEFAULT_DELAY_DHCP;
    common.timeout_http = DEFAULT_TIMEOUT_HTTP;
    common.timeout_mdns = DEFAULT_TIMEOUT_MDNS;
    common.timeout_dhcp = DEFAULT_TIMEOUT_DHCP;

    /* CONSIDER: If we want to redirect output to a file, simplest would be to
       use freopen(logfile,"w",stdout) to replace stdout for our execution. */

    // Disable stdin/stdout buffering:
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    fflush(stdout);

    // signals
    if (SIG_ERR == signal(SIGPIPE,SIG_IGN)) {
        fprintf(stderr,"Failed to set SIGPIPE ignore (%d) %s\n",errno,strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (SIG_ERR == signal(SIGINT,signal_handler)) {
        fprintf(stderr,"Failed to set SIGINT signal handler (%d) %s\n",errno,strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (SIG_ERR == signal(SIGHUP,signal_handler)) {
        fprintf(stderr,"Failed to set SIGHUP signal handler (%d) %s\n",errno,strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Process arguments:
    {
        int c;
        while (1) {
            int option = 0;

            c = getopt_long(argc,argv,"hvxw:u:g:f:m:l:d:i:e:y:a:b:c:t:p:q:r:s:zn:",opts,&option);
            if (-1 == c) {
                break;
            }

            switch (c) {
            default:
                fprintf(stderr,"Use \"%s --help\" for parameter information\n",argv[0]);
                exit(EXIT_FAILURE);

            case 'h': // help
                command_line_help(argv[0]);
                exit(EXIT_FAILURE);

            case 'v': // verbose
                if (common.log_level < UINT_MAX) {
                    common.log_level++;
                }
                break;

            case 'x': // silent
                common.ncurses = 0;
                common.silent = -1;
                break;

            case 'z': // disable-ncurses
                common.ncurses = 0;
                break;

            case 'w': // http-clients
                common.clients_http = arg_val("--http-clients",optarg,1,1024);
                break;

            case 'u': // http-list
                p_fnamelist_http = copystring(optarg,0);
                break;

            case 'g': // http-safe
                p_fnamelist_http_safe = copystring(optarg,0);
                break;

            case 'f': // http-unsafe
                p_fnamelist_http_unsafe = copystring(optarg,0);
                break;

            case 'm': // mdns-clients
                common.clients_mdns = arg_val("--mdns-clients",optarg,1,1024);
                break;

            case 'l': // mdns-list
                p_fnamelist_mdns = copystring(optarg,0);
                break;

            case 'd': // dhcp-clients
                common.clients_dhcp = arg_val("--dhcp-clients",optarg,1,1024);
                break;

            case 'i': // interface
                {
                    interface_t *p_head = NULL;
                    interface_t *p_tail = NULL;
                    char *p_arglist = optarg;

                    while (p_arglist && *p_arglist) {
                        char *p_sep = strchr(p_arglist,',');
                        char *p_copy = NULL;

                        if (p_sep) {
                            p_copy = copystring(p_arglist,(p_sep - p_arglist));
                            p_arglist = (p_sep + 1);
                        } else {
                            p_copy = copystring(p_arglist,0);
                            p_arglist = NULL;
                        }

                        {
                            interface_t *p_cptr = (interface_t *)calloc(1,sizeof(*p_cptr));
                            if (p_cptr) {
                                p_cptr->p_iface = copystring(p_copy,0);
                                if (p_head) {
                                    p_tail->p_next = p_cptr;
                                    p_tail = p_cptr;
                                } else {
                                    p_head = p_cptr;
                                    p_tail = p_cptr;
                                }
                            } else {
                                perror("OOM");
                                exit(EXIT_FAILURE);
                            }
                        }
                    }

# if 0 // DEBUG
                    {
                        interface_t *p_cptr;
                        printf("interfaces:\n");
                        for (p_cptr = p_head; p_cptr; p_cptr = p_cptr->p_next) {
                            printf(" %s\n",p_cptr->p_iface);
                        }
                    }
# endif // DEBUG

                    common.p_interfaces = p_head;
                }
                break;

            case 'e': // ehw // dhcp-iface
                common.p_hwiface = copystring(optarg,0);
                break;

            case 'y': // delay
                common.delay_common = arg_val("--delay",optarg,MIN_DELAY,MAX_DELAY);
                break;

            case 'a': // delay-http
                common.delay_http = arg_val("--delay-http",optarg,MIN_DELAY,MAX_DELAY);
                break;

            case 'b': // delay-mdns
                common.delay_mdns = arg_val("--delay-mdns",optarg,MIN_DELAY,MAX_DELAY);
                break;

            case 'c': // delay-dhcp
                common.delay_dhcp = arg_val("--delay-dhcp",optarg,MIN_DELAY,MAX_DELAY_DHCP);
                break;

            case 't': // timeout
                /* This older --timeout command-line option affects all the workers: */
                common.timeout_http = arg_val("--timeout",optarg,100,MAX_TIMEOUT);
                common.timeout_mdns = common.timeout_dhcp = common.timeout_http;
                break;

            case 'p': // timeout-http
                common.timeout_http = arg_val("--timeout-http",optarg,100,MAX_TIMEOUT);
                break;

            case 'q': // timeout-mdns
                common.timeout_mdns = arg_val("--timeout-mdns",optarg,100,MAX_TIMEOUT);
                break;

            case 'r': // timeout-dhcp
                common.timeout_dhcp = arg_val("--timeout-dhcp",optarg,100,MAX_TIMEOUT);
                break;

            case 's': // stagger
                common.stagger = arg_val("--stagger",optarg,0,MAX_STAGGER);
                break;

            case 'n': // dhcp-count
                common.count_dhcp = arg_val("--dhcp-count",optarg,1,MAX_DHCP_COUNT);
                break;
            }
        }

        if (optind < argc) {
            fprintf(stderr,"Too many arguments given\n");
            exit(EXIT_FAILURE);
        }

        if (0 == (common.clients_http | common.clients_mdns | common.clients_dhcp)) {
            fprintf(stderr,"At least one (or more) of --http-clients, --mdns_clients or --dhcp-clients needs to be specified\n");
            exit(EXIT_FAILURE);
        }

        if (NULL == common.p_hwiface) {
            common.p_hwiface = copystring(DEFAULT_HWIFACE,0);
        }

        if (common.clients_http) {
            strlist_t *p_default = NULL;
            strlist_t *p_safe = NULL;
            strlist_t *p_unsafe = NULL;
            size_t entries_default = 0;
            size_t entries_safe = 0;
            size_t entries_unsafe = 0;

            if ((NULL == p_fnamelist_http) && (NULL == p_fnamelist_http_safe) && (NULL == p_fnamelist_http_unsafe)) {
                fprintf(stderr,"--http-clients option needs at least one of --http-list, --http-safe or --http-unsafe supplied\n");
                exit(EXIT_FAILURE);
            }

            if (p_fnamelist_http) {
                if (NULL == (p_default = list_build(p_fnamelist_http,UT_DEFAULT,&entries_default))) {
                    exit(EXIT_FAILURE);
                }
            }
            if (p_fnamelist_http_safe) {
                if (NULL == (p_safe = list_build(p_fnamelist_http_safe,UT_SAFE,&entries_safe))) {
                    exit(EXIT_FAILURE);
                }
            }
            if (p_fnamelist_http_unsafe) {
                if (NULL == (p_unsafe = list_build(p_fnamelist_http_unsafe,UT_UNSAFE,&entries_unsafe))) {
                    exit(EXIT_FAILURE);
                }
            }

            data_http.p_head = p_default;
            if (data_http.p_head) {
                strlist_t *p_last = list_last(data_http.p_head);
                p_last->p_next = p_safe;
            } else {
                data_http.p_head = p_safe;
            }
            if (data_http.p_head) {
                strlist_t *p_last = list_last(data_http.p_head);
                p_last->p_next = p_unsafe;
            } else {
                data_http.p_head = p_unsafe;
            }

            data_http.entries = (entries_default + entries_safe + entries_unsafe);
            data_http.p_common = &common;
        }

        if (common.clients_mdns) {
            if (NULL == p_fnamelist_mdns) {
                fprintf(stderr,"--mdns-clients option needs supplied --mdns-list file containing <host>.local names\n");
                exit(EXIT_FAILURE);
            }

            if (NULL == (data_mdns.p_head = list_build(p_fnamelist_mdns,UT_DEFAULT,&data_mdns.entries))) {
                exit(EXIT_FAILURE);
            }

            data_mdns.p_common = &common;
        }

        if (common.clients_dhcp) {
            if (NULL == common.p_hwiface) {
                fprintf(stderr,"--dhcp-clients option needs --ehw network interface supplied\n");
                exit(EXIT_FAILURE);
            }
            if ((0 == common.count_dhcp) && (NULL == common.p_interfaces)) {
                fprintf(stderr,"--dhcp-clients option needs at least one --interface network interface supplied when --dhcp-count not specified\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    if (0xFFFFFFFF == common.delay_http) {
        common.delay_http = common.delay_common;
    }
    if (0xFFFFFFFF == common.delay_mdns) {
        common.delay_mdns = common.delay_common;
    }
    /* Following should no longer be exercised since we have an explicit DHCP
       default delay now: */
    if (0xFFFFFFFF == common.delay_dhcp) {
        common.delay_dhcp = common.delay_common;
    }

    openlog("cnetgen",(LOG_CONS | LOG_ODELAY),LOG_DAEMON);

    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_JOINABLE);

#if 0 // if needed (though unlikely)
    //pthread_attr_getstacksize to find default
    //pthread_attr_setstacksize
#endif

    /* We strictly do not need this as a seperate thread, but it may be useful
       for future synchronisation. */
    // UI thread:
    {
        int error = pthread_create(&tid_display,&attr,loop_control,(void *)&common);
        if (error) {
            fprintf(stderr,"Failed to create loop control thread with error %d\n",error);
            exit(EXIT_FAILURE);
        }
    }

    // Workers:
    if (common.clients_http) {
        // Initialize libcurl before any threads are started:
        curl_global_init(CURL_GLOBAL_ALL);
        // CONSIDER: Use of curl_global_init_mem() and provide calls for serialising memory operations - maybe that is why the SSL world is failing if the memory world is not thread safe

        common.tid_http = calloc(common.clients_http,sizeof(pthread_t));
        if (NULL == common.tid_http) {
            perror("OOM");
            exit(EXIT_FAILURE);
        }

        {
            unsigned int idx;

            for (idx = 0; (idx < common.clients_http);) {
                int error;

                if (idx && common.stagger) {
                    usleep(common.stagger * 1000);
                }

                error = pthread_create(&common.tid_http[idx],&attr,thread_http,(void *)&data_http);
                if (error) {
                    fprintf(stderr,"Failed to start HTTP thread %u with error %d\n",idx,error);
                    common.clients_http--;
                } else {
                    idx++;
                }
            }
        }
    }

    if (common.clients_mdns) {
        if (sizeof(pid_t) > sizeof(u_int32_t)) {
            fprintf(stderr,"Unexpected mismatch with pid_t size\n");
            exit(EXIT_FAILURE);
        }

        common.tid_mdns = calloc(common.clients_mdns,sizeof(pthread_t));
        if (NULL == common.tid_mdns) {
            perror("OOM");
            exit(EXIT_FAILURE);
        }

        {
            unsigned int idx;

            /* For the moment where we just transmit UDP mDNS questions, and do
               not care about any responses we can share the socket(s) between all
               the threads, since sendto() will act atomic in nature. */
            interface_t *p_cptr;
            unsigned int nsocks = 0;

            for (p_cptr = common.p_interfaces; p_cptr; p_cptr = p_cptr->p_next) {
                nsocks++;
            }
            if (0 == nsocks) {
                nsocks = 1;
            }

            int *p_svec = calloc(nsocks,sizeof(int));
            if (NULL == p_svec) {
                perror("OOM svecs");
                exit(EXIT_FAILURE);
            }

            sockset_t *p_sockset = calloc(1,sizeof(*p_sockset));
            if (NULL == p_sockset) {
                perror("OOM sockset");
                exit(EXIT_FAILURE);
            }

            p_cptr = common.p_interfaces;
            for (idx = 0; (idx < nsocks); idx++) {
                int sockfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
                if (sockfd < 0) {
                    perror("socket");
                    exit(EXIT_FAILURE);
                }

                if (p_cptr && p_cptr->p_iface) {
                    size_t insize = strlen(p_cptr->p_iface);
                    if (insize <= IFNAMSIZ) {
                        int rc = setsockopt(sockfd,SOL_SOCKET,SO_BINDTODEVICE,(void *)p_cptr->p_iface,insize);
                        if (rc < 0) {
                            perror("SO_BINDTODEVICE");
                            exit(EXIT_FAILURE);
                        }
                    } else {
                        fprintf(stderr,"Supplied interface name \"%s\" is too long (limit IFNAMSIZ %d)\n",p_cptr->p_iface,IFNAMSIZ);
                        exit(EXIT_FAILURE);
                    }

                    p_cptr = p_cptr->p_next;
                }

                p_svec[idx] = sockfd;
            }

            p_sockset->num = nsocks;
            p_sockset->p_svec = p_svec;

            data_mdns.u.p_private = (void *)p_sockset;

            for (idx = 0; (idx < common.clients_mdns);) {
                int error;

                if (idx && common.stagger) {
                    usleep(common.stagger * 1000);
                }

                error = pthread_create(&common.tid_mdns[idx],&attr,thread_mdns,(void *)&data_mdns);
                if (error) {
                    fprintf(stderr,"Failed to start mDNS thread %u with error %d\n",idx,error);
                    common.clients_mdns--;
                } else {
                    idx++;
                }
            }
        }
    }

    if (common.clients_dhcp) {
        data_dhcp.p_common = &common;
        data_dhcp.p_head = NULL; // not used for DHCP
        data_dhcp.entries = 0;

        {
            memset(&dhcpinfo,'\0',sizeof(dhcpinfo));

            dhcpinfo.stats_total.min = 0xFFFFFFFF;
            dhcpinfo.stats_offer.min = 0xFFFFFFFF;
            dhcpinfo.stats_ack.min = 0xFFFFFFFF;
        }

        data_dhcp.u.p_private = &dhcpinfo;

        /* If the user has not supplied an explicit --dhcp-count then we use the
           number of supplied interfaces as our default: */
        if (0 == common.count_dhcp) {
            interface_t *p_cptr;
            uint32_t nmacs = 0;

            for (p_cptr = common.p_interfaces; p_cptr; p_cptr = p_cptr->p_next) {
                nmacs++;
            }
            if (0 == nmacs) {
                nmacs = 1;
            }
            common.count_dhcp = nmacs;
        }

        /* We now have a single libpcap handler thread that we manage
           --dhcp-clients in-flight requests for. */
        common.threads_dhcp = 1;
        common.tid_dhcp = calloc(common.threads_dhcp,sizeof(pthread_t));
        if (NULL == common.tid_dhcp) {
            perror("OOM");
            exit(EXIT_FAILURE);
        }

        int error = pthread_create(&common.tid_dhcp[0],&attr,thread_dhcp,(void *)&data_dhcp);
        if (error) {
            fprintf(stderr,"Failed to start DHCP thread with error %d\n",error);
            common.threads_dhcp--;
        }
    }

    // All threads started

    // Wait for UI thread to terminate:
    {
        void *status;
        int error = pthread_join(tid_display,&status);
        if (error) {
            fprintf(stderr,"Error %d from pthread_join of main display thread\n",error);
        } else {
            //fprintf(stderr,"DBG: completed display thread with status %p\n",status);
        }
    }

    // silent output on termination:
    if (common.silent) {
        if (common.clients_http) {
            printf("HTTP %10u thread%s : %10u completed iteration%s : %10u pass%s : %10u failure%s\n",
                   common.clients_http,((1 == common.clients_http) ? " " : "s"),
                   common.http_iters,((1 == common.http_iters) ? " " : "s"),
                   common.http_pass,((1 == common.http_pass) ? "  " : "es"),
                   common.http_fail,((1 == common.http_fail) ? " " : "s"));
        }
        if (common.clients_mdns) {
            printf("mDNS %10u thread%s : %10u completed iteration%s : %10u pass%s : %10u failure%s\n",
                   common.clients_mdns,((1 == common.clients_mdns) ? " " : "s"),
                   common.mdns_iters,((1 == common.mdns_iters) ? " " : "s"),
                   common.mdns_pass,((1 == common.mdns_pass) ? "  " : "es"),
                   common.mdns_fail,((1 == common.mdns_fail) ? " " : "s"));
        }
        if (common.clients_dhcp) {
            printf("DHCP %10u thread%s :                                 : %10u pass%s : %10u failure%s\n",
                   common.clients_dhcp,((1 == common.clients_dhcp) ? " " : "s"),
                   common.dhcp_pass,((1 == common.dhcp_pass) ? "  " : "es"),
                   common.dhcp_fail,((1 == common.dhcp_fail) ? " " : "s"));
        }
        printf("\n\n");
    }

    // Cleanup:
    if (common.clients_http) {
        if (common.http_pass | common.http_fail) {
            list_dump(data_http.p_head);
        }

        list_free(data_http.p_head);
        curl_global_cleanup();
    }

    if (common.clients_mdns) {
        list_free(data_mdns.p_head);
        // We only reach here if we have created the socket(s):
        {
            sockset_t *p_sockset = (sockset_t *)(data_mdns.u.p_private);
            if (p_sockset) {
                unsigned int idx;
                for (idx = 0; (idx < p_sockset->num); idx++) {
                    close(p_sockset->p_svec[idx]);
                }
                (void)free(p_sockset);
            }
        }
    }

    if (common.clients_dhcp) {
        if (dhcpinfo.stats_total.count) {
            printf("# DHCP performance (%u successful transaction%s) values in milliseconds:\n",dhcpinfo.stats_total.count,((1 == dhcpinfo.stats_total.count) ? "" : "s"));
            printf("success_count,offer_min,offer_avg,offer_max,ack_min,ack_avg,ack_max,total_min,total_avg,total_max\n");
            printf("%u",dhcpinfo.stats_total.count);
            printf(",%u,%u,%u",dhcpinfo.stats_offer.min,(uint32_t)(dhcpinfo.stats_offer.total / dhcpinfo.stats_offer.count),dhcpinfo.stats_offer.max);
            printf(",%u,%u,%u",dhcpinfo.stats_ack.min,(uint32_t)(dhcpinfo.stats_ack.total / dhcpinfo.stats_ack.count),dhcpinfo.stats_ack.max);
            printf(",%u,%u,%u\n",dhcpinfo.stats_total.min,(uint32_t)(dhcpinfo.stats_total.total / dhcpinfo.stats_total.count),dhcpinfo.stats_total.max);
        } else {
            printf("# No successful DHCP transactions\n");
        }
    }

    {
        interface_t *p_cptr = common.p_interfaces;
        while (p_cptr) {
            interface_t *p_release = p_cptr;
            p_cptr = p_cptr->p_next;
            if (p_release->p_iface) {
                (void)free((char *)(p_release->p_iface));
            }
            (void)free(p_release);
        }
    }

    if (p_fnamelist_http) {
        (void)free(p_fnamelist_http);
    }
    if (p_fnamelist_http_safe) {
        (void)free(p_fnamelist_http_safe);
    }
    if (p_fnamelist_http_unsafe) {
        (void)free(p_fnamelist_http_unsafe);
    }
    if (p_fnamelist_mdns) {
        (void)free(p_fnamelist_mdns);
    }

    if (common.tid_dhcp) {
        (void)free(common.tid_dhcp);
    }
    if (common.tid_mdns) {
        (void)free(common.tid_mdns);
    }
    if (common.tid_http) {
        (void)free(common.tid_http);
    }

    if (common.p_hwiface) {
        (void)free((void *)common.p_hwiface);
    }

    (void)msgctl(common.qid_dhcp,IPC_RMID,NULL);
    (void)msgctl(common.qid,IPC_RMID,NULL);

    pthread_attr_destroy(&attr);

    return EXIT_SUCCESS;
}

//=============================================================================
// EOF cnetgen.c
