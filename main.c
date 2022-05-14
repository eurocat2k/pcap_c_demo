/**
 * Name    
 *          pcaptest
 * Description    
 *          simple packet filter program with command line arguments using kqueue event loop
 * Usage
 *          pcaptest [-h|--help] [-i|--if <device name> [filter]] 
 *
 *          where
 * 
 *          -h or --help prints help info of usage
 *          -i <devive> or --if <device> sets the capture device
 *          filter is the text used to compile and set the pcap filter (optional)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>
#include <getopt.h>
#include <signal.h>
#include <ctype.h>
#include <assert.h>
#include <err.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/event.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>


#define _U_

void usage(const char*pname);
char *trim(char *s);
void hexdump(const char*title, const void* data, size_t size);
void got_packet(u_char *user, const struct pcap_pkthdr *h,const u_char *byte);
void sig_handler(int signal);

#ifndef PCAP_BUF_SIZE
#define PCAP_BUF_SIZE (1600)
#endif //!PCAP_BUF_SIZE

#ifndef PCAP_SNAP_SIZE
#define PCAP_SNAP_SIZE 65535
#endif  //!PCAP_SNAP_SIZE

#ifndef PCAP_TIMEOUT
#define PCAP_TIMEOUT    (100)
#endif  //!PCAP_TIMEOUT

#ifndef FILTER_LEN
#define FILTER_LEN (256)
#endif  //!FILTER_LEN

#ifndef KEV_SIZE
#define KEV_SIZE (8)
#endif  //!KEV_SIZE

static int hflag;
pcap_t *gphandle = NULL;
struct bpf_program* gbfp = NULL;

int main(int argc, char **argv) {
    /*
     * pcap handle 
     */
    static pcap_t *phandle = NULL;
    /* 
     * bpf filter struct
     */
    struct bpf_program bfp = {0};
    /*
     * selectable pcap handle derived file descriptor 
     */
    int pcap_fd = -1;
    /*
     * pcap header 
     */
    struct pcap_pkthdr *pkh = NULL;
    /*
     *  pcap_buff - PCAP_BUF_SIZE octets size - buffer to store captured packages
     *  errbuf - PCAP_ERRBUF_SIZE octets size - buffer for PCAP's error texts
     */
    char pcap_buff[PCAP_BUF_SIZE], errbuf[PCAP_ERRBUF_SIZE];
    /*
     * filter_buff[] - FILTER_LEN octets size - for filter text
     * fp - pointer to filter_buff
     */
    char filter_buff[FILTER_LEN] = {0}, *fptr = &filter_buff[0];
    /*
     * c - param character or option indicator character
     * dflag - device setting flag, 1: if set, 0: if not set
     */
    int c, dflag = 0;
    /*
     * filter - the filter text after trimming
     * device - the capture device name
     * tmp - for asprintf and free cycle (not used now)
     * params - the getopt_long parameter string, h: for help, i: for capture device name
     */
    char *filter = NULL, *device = NULL, *tmp, *params = "hi:";
    /*
     * option long_options - array of valid optios according to params string
     */
    static struct option long_options[] = {
        {"help", no_argument,       &hflag, 1},
        {"if"  , required_argument, 0,    'i'},
        {0, 0, 0, 0}
    };
    if (getuid()) {
        printf(" Error: user must have root privileges to execute this program!\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    /*
     * process of command line options...
     */
    while(1) {
        int option_index = 0;
        c = getopt_long (argc, argv, params, long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
            case 0:
                // long format for simple params - without arguments
                if (long_options[option_index].flag != 0) {
                    // printf(" optindex %d flag %d\n", option_index, *(long_options[option_index].flag));
                    break;
                }
                // printf (" option %s", long_options[option_index].name);
                if (optarg) {
                    // printf (" with arg %s", optarg);
                }            
                // printf ("\n");
            break;
            case 'i':
                // we got capture device name
                printf (" Capture device: `%s'\n", optarg);
                dflag = 1;
                device = optarg;
            break;
            case '?':
                /* getopt_long already printed an error message. */
            break;
            case 'h':
            default:
                // something not ok, or help triggered
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            break;
        }
    }
    /*
     * if help
     */
    if (hflag) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    /*
     * if no help, but no device - which is mandatory otherwise
     */
    if (device == NULL) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    // get remaining options as filter text
    if (optind < argc) {
        //   printf ("non-option ARGV-elements: ");
        while (optind < argc) {
            char *s = argv[optind++];
            int len = strlen(s);
            if (fptr == NULL) {
                asprintf(&filter, "%.*s", len, s);
                if ((strlen(fptr) + len) < FILTER_LEN) {
                    strncat(fptr, filter, len);
                }
                fptr = trim(fptr);
            } else {
                asprintf(&filter, " %.*s", len+1, s);
                if ((strlen(fptr) + len + 1) < FILTER_LEN) {
                    strncat(fptr, filter, len + 1);
                }
                fptr = trim(fptr);
            }
            free(filter);   // free
            filter = NULL;  // and prepare for the next one
        }
    }
    /*
     * if there is filter text then set it now
     */
    if (strlen(fptr)) {
        printf(" Filter: %s\n", fptr);
        filter = fptr;
    }
    /* 
     * Signal handling
     */
    signal(SIGABRT, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGKILL, sig_handler);
    /*
     * PCAP initialisation 
     */
#ifdef PCAP_CREATE_LIVE
    // we setup and initialize pcap handle calling pcap_open_live
    if ((phandle = pcap_open_live(device, PCAP_SNAP_SIZE, 1, 1000, errbuf)) == NULL){
        printf(" Error: pcap_open_live failed\n");
        goto end;
    }
#else
    // Preparation - options settings 
    // create pcap handle
    if ((phandle = pcap_create(device, errbuf)) == NULL) {
        printf(" Error: pcap_open_live failed\n");
        goto end;
    }
    // set buffer size
    if (pcap_set_buffer_size(phandle, PCAP_BUF_SIZE) != 0) {
        pcap_perror(phandle, "set buffer size");
        goto error;
    }
    // set pcap buffer timeout
    if (pcap_set_timeout(phandle, PCAP_TIMEOUT) != 0) {
        pcap_perror(phandle, "set timeout");
        goto error;
    }
    // set snaplen
    if (pcap_set_snaplen(phandle, 0x0FFFF) != 0) {
        pcap_perror(phandle, "set snaplen to default");
        goto error;
    }
    // switch to promisc mode
    if (pcap_set_promisc(phandle, 1) != 0) {
        pcap_perror(phandle, "set promisc mode");
        goto error;
    }
    // set nonblocking
    if (pcap_setnonblock(phandle, 1, errbuf) != 0) {
        pcap_perror(phandle, "set nonblocking mode");
        goto error;
    }
    // Finally activate pcap handle - no more options modification enabled after this
    if (pcap_activate(phandle) != 0) {
        pcap_perror(phandle, "activation");
        goto error;
    }
#endif
    gphandle = phandle; // save global pointer - signal handlers needed
    // compile filter text
    if (pcap_compile(phandle, &bfp, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_perror(phandle, "compile filter");
        goto error;
    }
    // set filter
    if (pcap_setfilter(phandle, &bfp) != 0) {
        pcap_perror(phandle, "set filter");
        goto error;
    }
    gbfp = &bfp;    // save filter or simply free it after this
    if (gbfp) {
        pcap_freecode(gbfp);
        gbfp = NULL;        // we do not care later on
    }
    // get selectable file descriptor
    if ((pcap_fd = pcap_get_selectable_fd(phandle)) <= 0) {
        pcap_perror(phandle, "get selectable filedescriptor");
        goto error;
    }
    printf(" Pcap_fd: %d\n", pcap_fd);
    /*
     * KQUEUE initialization
     */
    struct kevent event, events[KEV_SIZE];
    int kq;
    assert((kq = kqueue()) != -1);
    EV_SET(&event, pcap_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    assert(-1 != kevent(kq, &event, 1, NULL, 0, NULL));
    /* 
     * MAIN LOOP 
     */
    for (;;) {
        int ret = kevent(kq, NULL, 0, (struct kevent*)&events, KEV_SIZE, NULL);
        if (ret == -1) {
            err(EXIT_FAILURE, "kevent wait");
        } else if (ret > 0) {
            for (int i = 0; i < KEV_SIZE; i++) {
                int ev_id = events[i].ident;
                if (ev_id == pcap_fd) {
                    pcap_dispatch(phandle, -1, got_packet, NULL);
                    // pcap_next(phandle, &pkh);
                    // printf("Something was wricaptured on '%s'\n", device);
                    // if (NULL != pkh) {
                    //     printf(" pkh->caplen: %d\n", pkh->caplen);
                    //     printf("    pkh->len: %d\n", pkh->len);
                    // }
                }
            }
        }
    }
error:
    if (phandle != NULL) {
        pcap_close(phandle);
    }
end:
    // 
    return EXIT_SUCCESS;
}
/**
 * @name   usage
 * @note   prints usage
 * @param  char* pname the basenamed argv[0]
 * @retval None
 */
void usage(const char*pname) {
    printf(" %s [-h|--help] [-i|--if <name> [filter_text]]\n", pname);
    printf("\n  where\n");
    printf("\t-h or --help - this help\n");
    printf("\t-i or --if   - device name used to pcap packets\n");
    printf("\tfilter_text  - the filter applied upon pcap processing\n\n");
    return;
}
// helper for trim
char *ltrim(char *s) {
    while(isspace(*s)) s++;
    return s;
}
// helper for trim
char *rtrim(char *s) {
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}
/**
 * @name   trim
 * @note   removes spaces from the beginnig and end of the param - s
 * @param  char *s the string to be trimmed 
 * @retval trimmed string - s
 */
char *trim(char *s) {
    return rtrim(ltrim(s)); 
}
/**
 * @name   got_packet
 * @note   pcap catched packet processor
 * @param  unsigned char *user - user defined parameter (need to be casted as requied)
 * @param  const struct pcap_pkthdr * h - pcap header
 * @param  const unsigedn char *byte - pointer to the buffer, where caught packets stored during the operation
 * @retval None
 */
void got_packet(u_char *user, const struct pcap_pkthdr *h,const u_char *byte){
    printf(" caption size: %d\n", h->caplen);
    printf("          len: %d\n", h->len);
    hexdump(NULL, (const void *)byte, (size_t)h->caplen);
    return;
}
/**
 * @name   hexdump
 * @note   dumps data in hex output format
 * @param  const char *title - title or NULL
 * @param  const void *data  - buffer to be hexdumped 
 * @param  size_t size       - buffer size to be hexdumped
 * @retval None
 */
void hexdump(const char*title _U_, const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	if (title) {
		fprintf(stdout, "BEGIN %s\n", title);
	}
	for (i = 0; i < size; ++i) {
		fprintf(stdout, "%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(stdout, " ");
			if ((i+1) % 16 == 0) {
				fprintf(stdout, "|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(stdout, " ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(stdout, "   ");
				}
				fprintf(stdout, "|  %s \n", ascii);
			}
		}
	}
	if (title) {
		fprintf(stdout, "END %s\n", title);
	}
}
void sig_handler(int sig) {
    switch(sig) {
        default:
            printf("phandle: %p\n", gphandle);
            if (gbfp) {
                pcap_freecode(gbfp);
            }
            if (gphandle) {
                pcap_close(gphandle);
            }
            exit(0);
        break;
    }
}