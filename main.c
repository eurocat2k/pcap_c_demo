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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h> 
#include <netinet/if_ether.h>

#include "cap.h"

#define _U_

void usage(const char*pname);
char *trim(char *s);
void hexdump(const char*title, const void* data, size_t size);
void got_packet(u_char *user, const struct pcap_pkthdr *h,const u_char *byte);
void sig_handler(int signal);
bool is_ipv4_multicast(const char* ipstr);

// new wrapper functions
u_int16_t get_ethernet_type(void *base);
void *get_ip_hdr(void *base);
void *get_tcp_hdr(void *base);
void *get_udp_hdr(void *base);
void *get_payload(void* base, size_t *size);

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
                    if (pcap_datalink(phandle) == DLT_EN10MB) {
                        //  we work with ethernet frames now
                        pcap_dispatch(phandle, -1, got_packet, NULL);
                    }
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
void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet){
    struct {
        uint8_t dlt_eth: 1;     // ethernet or not
        uint8_t eth_ipv4: 1;        // is IPv4 ethernet
        uint8_t eth_ipv6: 1;        // is IPv6 ethernet
        uint8_t eth_mcast_v4: 1;    // is multicast v4 ethernet
        uint8_t eth_mcast_v6: 1;    // is multicast v6 ethernet
        uint8_t eth_vlan_mcast: 1;  // is VLAN multicast
        uint8_t eth_broadcast: 1;   // is broadcast address
        uint8_t eth_vlan: 1;    // VN-tagged LAN ethernet frame
        uint8_t ipv4: 1;    // is ipv4
        uint8_t ipv6: 1;    // is ipv6
        uint8_t ip_mcast;   // is valid group - call is_ipv4_multicast(...)
        uint8_t udp: 1;     // is udp
        uint8_t tcp: 1;     // is tcp
    } fspec = {0};
    const struct ether_header *ethernet = NULL;    /* The ethernet header */
    const struct ether_vlan_header *vlan_ethernet = NULL;  /* The VN-tagged ethernet frame header */
    const struct ip *ip;                    /* The IP header */
    const struct tcphdr *tcp;               /* The TCP header */
    const struct udphdr *udp;               /* The UDP header */
    const unsigned char *payload;           /* Packet payload */
    char *ether_header = NULL, *etmp;       /* pointer to the ethernet header */
    char *ip_header = NULL, *itmp;          /* pointer to the IP header */
    char *udp_header = NULL, *utmp;         /* pointer to the IP header */
    int srcport = -1;                       /* source port */
    int dstport = -1;                       /* destination port */
    int size_ip;                            /* sizeof IP header */
    int size_tcp;                           /* sizeof TCP header */
    int size_udp;                           /* sizeof UDP header */
    unsigned int size_payload = 0;          /* sizeof payload */
    unsigned int total_len = h->caplen - sizeof(struct pcap_pkthdr);    // total packet size without PCAP header
    unsigned short ether_type = 0;          /* the ethernet type */
    unsigned short vlan_type = 0;           /* VLAN ethernet type */
    unsigned short vlan_tag = 0;            /* VLAN tag */
    unsigned short vlan_proto = 0;          /* VLAN protocol */
    unsigned short vlan_encap_proto = 0;    /* VLAN encapsulation protocol */
    // 
    fspec.dlt_eth = 1;  // this is ethernet frame
    // 
    // print out PCAP header info
    printf("         caption size: %d\n", h->caplen);
    printf("                  len: %d\n", h->len);
    printf("  ethernet frame size: %d\n", ETHER_HDR_LEN);
    // detect ethernet type
    ethernet = (struct ether_header*)(packet);    // we do expect ethernet frames
    ether_type = ETHER_TYPE(ethernet->ether_type);
    switch(ether_type) {
        case ETHERTYPE_IP:
            fspec.eth_ipv4 = 1;
            printf(" Ethernet IPv4 frame detected\n");
            if (ETHER_IS_MULTICAST(ethernet->ether_dhost)) {
                fspec.eth_mcast_v4 = 1;
                printf(" Ethernet IPv4 multicast frame detected\n");
            }
            // print src/dst MAC addresses
            printf(" ethernet src: %s\n", ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
            printf(" ethernet dst: %s\n", ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
            // get source and dst IP address, type and protocol
            // locate IP header first
            ip = (struct ip*)(packet + ETHER_HDR_LEN);
            //  check IP header validity
            if (ip->ip_hl < 5) {
                printf(" Invalid IP header, return without further processing.\n");
                return;
            }
            size_ip = IP_HL(ip)*4;
            printf(" Ethernet header size: %d\n", (int)sizeof(struct ether_header));
            printf(" Sizeof IP header: %d\n", (unsigned short)size_ip);
            printf("       IP version: %d\n", ip->ip_v);
            printf(" IP header length: %d\n", ip->ip_hl);
            printf("  IP total length: %d\n", size_ip);
            printf("   IP src address: %s\n", inet_ntoa(ip->ip_src));
            printf("   IP dst address: %s\n", inet_ntoa(ip->ip_dst));
            printf(" IP protocol type: %d\n", ip->ip_p);
            printf("           IP TTL: %d\n", (unsigned short)ip->ip_ttl);
            if (is_ipv4_multicast(inet_ntoa(ip->ip_dst))) {
                fspec.ip_mcast = 1;
            }
            // we deal with IPv4 UPD MULTICAST frames now
            if (ip->ip_p == IPPROTO_UDP) {
                fspec.udp = 1;
                /* define payload pointer */
                payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
	            /* compute tcp payload (segment) size */
	            size_payload = ntohs(ip->ip_len) - (size_ip + sizeof(struct udphdr));
                payload = packet + sizeof(struct ether_header) + size_ip + sizeof(struct udphdr);
                udp = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                srcport = (unsigned short)(udp->uh_sport>>8|udp->uh_sport<<8);
                dstport = (unsigned short)(udp->uh_dport>>8|udp->uh_dport<<8);
                printf(" UDP src port: %d\n", srcport);
                printf(" UDP dst port: %d\n", dstport);
                printf(" Sum headers size: %d\n", (int)(sizeof(struct ether_header) + htons(ip->ip_len) + sizeof(struct udphdr)));
            }
            // printout the payload in hex
            printf("   payload length: %d\n", size_payload);
            hexdump("payload", (const void *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)), (size_t)size_payload);
            // 
        break;
        case ETHERTYPE_IPV6: // TODO!
            fspec.eth_ipv6 = 1;
            printf(" Ethernet IPv6 frame detected\n");
            if (ETHER_IS_IPV6_MULTICAST(ethernet->ether_dhost)) {
                fspec.eth_mcast_v6 = 1;
            }
            // print src/dst MAC addresses
            printf(" ethernet src: %s\n", ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
            printf(" ethernet dst: %s\n", ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
            // 
            hexdump("packet", (const void *)packet, (size_t)h->caplen); // print entire pcap packet - without pcap header
            // 
        break;
        case ETHERTYPE_VLAN:
            fspec.eth_vlan = 1;
            printf(" Ethernet VN-tagged frame detected\n");
            vlan_ethernet = (struct ether_vlan_header*)packet;
            if (ETHER_IS_MULTICAST(vlan_ethernet->evl_dhost)) {
                fspec.eth_vlan_mcast = 1;
                printf(" Ethernet VN-tagged multicast frame detected\n");
            }
            // print src/dst MAC addresses
            printf(" VLAN ethernet src: %s\n", ether_ntoa((const struct ether_addr *)&vlan_ethernet->evl_shost));
            printf(" VLAN ethernet dst: %s\n", ether_ntoa((const struct ether_addr *)&vlan_ethernet->evl_dhost));
            vlan_tag = (unsigned short)((vlan_ethernet->evl_tag >> 8) | (vlan_ethernet->evl_tag << 8));
            printf("          VLAN tag: %d [0x%04X]\n", vlan_tag, vlan_tag);
            vlan_proto = (unsigned short)(vlan_ethernet->evl_proto>>8|vlan_ethernet->evl_proto<<8);
            printf("        VLAN proto: %d [0x%04X]\n", vlan_proto, vlan_proto);
            vlan_encap_proto = (unsigned short)(vlan_ethernet->evl_encap_proto>>8|vlan_ethernet->evl_encap_proto<<8);
            printf(" VLAN encapsulation protocol: %d [0x%04X]\n", vlan_encap_proto, vlan_encap_proto);
            switch (vlan_proto) {
                case ETHERTYPE_IP:
                    ip = (struct ip*)(packet + sizeof(struct ether_vlan_header));
                    if (ip->ip_hl < 5) {
                        printf(" Invalid IP header, return without further processing.\n");
                        return;
                    }
                    size_ip = IP_HL(ip)*4;
                    total_len = size_ip;
                    printf(" VLAN Ethernet header size: %d\n", (int)size_ip);
                    printf(" Sizeof IP header: %d\n", (unsigned short)size_ip);
                    printf("       IP version: %d\n", ip->ip_v);
                    printf(" IP header length: %d\n", ip->ip_hl);
                    printf("  IP total length: %d\n", size_ip);
                    printf("   IP src address: %s\n", inet_ntoa(ip->ip_src));
                    printf("   IP dst address: %s\n", inet_ntoa(ip->ip_dst));
                    printf(" IP protocol type: %d\n", ip->ip_p);
                    printf("           IP TTL: %d\n", (unsigned short)ip->ip_ttl);
                    if (is_ipv4_multicast(inet_ntoa(ip->ip_dst))) {
                        fspec.ip_mcast = 1;
                    }
                    // we deal with IPv4 UPD MULTICAST frames now
                    if (ip->ip_p == IPPROTO_UDP) {
                        fspec.udp = 1;
                        payload = packet + sizeof(struct ether_vlan_header) + size_ip + sizeof(struct udphdr);
                        size_payload = htons(ip->ip_len) - (size_ip + sizeof(struct udphdr));
                        udp = (struct udphdr *)(packet + sizeof(struct ether_vlan_header) + sizeof(struct ip));
                        srcport = (unsigned short)(udp->uh_sport>>8|udp->uh_sport<<8);
                        dstport = (unsigned short)(udp->uh_dport>>8|udp->uh_dport<<8);
                        printf(" UDP src port: %d\n", srcport);
                        printf(" UDP dst port: %d\n", dstport);
                        printf(" Sum headers size: %d\n", (int)(sizeof(struct ether_vlan_header) + htons(ip->ip_len) + sizeof(struct udphdr)));
                    }
                    // printout the payload in hex
                    printf("   payload length: %d\n", (int)(h->caplen-(sizeof(struct ether_vlan_header)+sizeof(struct ip)+sizeof(struct udphdr))));
                    hexdump("payload", (const void *)(packet + sizeof(struct ether_vlan_header) + sizeof(struct ip) + sizeof(struct udphdr)), (size_t)size_payload);
                    hexdump("raw packet", (const void *)packet, (size_t)h->caplen); // print entire pcap packet - without pcap header
                    // 
                break;
                case ETHERTYPE_IPV6:
                    // TODO! parse IPv6
                break;
                default:
                break;
            }
            // 
            // hexdump("packet", (const void *)packet, (size_t)h->caplen); // print entire pcap packet - without pcap header
        break;
    }
    
    // hexdump("packet", (const void *)packet, (size_t)h->caplen); // print entire pcap packet - without pcap header
    size_t plen = 0;
    void *pyld = get_payload((void *)packet, &plen);
    printf(" get_payload(): payload = %p [%p], payload length = %d\n", pyld, packet, (int)plen);
    
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
/**
 * @name   sig_handler
 * @note   executes this code at event of signal
 * @param  int sig - signal number
 * @retval None
 */
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
/**
 * @name   is_ipv4_multicast
 * @note   validates IPv4 address, checking if it falls into the range of MCAST address pool.
 *         we will check only first byte of IPv4 and if it is in range from 224 to 239, then 
 *         it shoul represent multicast IP.
 * @param  const char* ip - the IP address in "x.x.x.x" for in case of IPv4
 * @retval true if valid otherwise false
 */
bool is_ipv4_multicast(const char* ipstr){
#ifndef IPV4_ADDR_STR_MAX_LEN
#define IPV4_ADDR_STR_MAX_LEN   (15)    // NNN.NNN.NNN.NNN
#endif
    int len = 0;                // 
    struct in_addr addr = {0};  // inet_aton conversion destination object
    char *ip_val = NULL;        // casted struct in_addr pointer
    if (NULL != ipstr) {
        len = strlen(ipstr);
        len = (len <= IPV4_ADDR_STR_MAX_LEN) ? len : IPV4_ADDR_STR_MAX_LEN; // do not allow longer string other than valid IPv4 address string!
        if (inet_aton(ipstr, (struct in_addr *)&addr)) {
            // string is success fully validated and converted
            ip_val = (char *)&addr;
            uint8_t octet = ip_val[0];
            if(octet >=  224 && octet <= 239){
                return true;
            }
        }
    }
    return false;
}
/**
 * @name   get_ethernet_type
 * @note   get ethernet type of the ethernet packet
 * @param  void *base - pointer to the captured packet data
 * @retval unsigned short - in byte ordered (swapped) - value of ethernet type
 */
u_int16_t get_ethernet_type(void *base) {
    assert(base);
    uint16_t ether_type = ntohs(*(uint16_t *)(base + ETHER_ADDR_LEN + ETHER_ADDR_LEN));
    return ether_type;
}
/**
 * @name   get_ip_hdr
 * @note   locates IP header struct in various cases - DLT is ethernet, if it does not use VLAN tagging,
 *         then IP header starts at location right after 2 x 6 bytes of MAC addresses (dst and src) plus
 *         two bytes with ethernet type. First of all this type value need to be checked. Depending on
 *         its value we can set up the offset of the IP header. If ethernet type is 0x0800, then we
 *         shall add 14 bytes offset to the very beginning of the packet pointer - containing the two
 *         MAC addresses - 12 bytes - and the type information with another two of them (12 + 2 = 14).
 * 
 *         If type is 0x8100, then we need to calculate a bit more bytes in the header. Additional 4
 *         octets given into the header structure. Therefore the base pointer need to be extended 18
 *         bytes offset to reach IP header location.
 *         Those additional four bytes contains the followig data:
 *         
 *         2 bytes for ethernet type - as before - but now it refers to the VLAN tagged value (0x8100),
 *         in this case the next two contains the VLAN TAG - or VLAN ID - on another 2 bytes.
 * 
 *         Then the former 2 bytes as if were no VLAN TAG in the frame - the type of ethernet in the
 *         VLAN tagged frame. For example if it is 0x0800, then we know we deal with IPv4 ethernet packet.
 *         
 *         Any other case - and it is true for both scenarios - the gap between the base pointer and the
 *         payload depends on ethernet type value and the size of the correlated structures.
 * 
 *         This function handles only IPv4 ethernet types any other cases returns NULL.
 * @param  void *base - the pointer to the very beginning of the captured packet.
 * @retval pointer to the IP header
 */
void *get_ip_hdr(void *base) {
    assert(base);
    // If frame is not ethernet retun NULL
    // uint16_t ether_type = ntohs(*(uint16_t *) (base + ETHER_ADDR_LEN + ETHER_ADDR_LEN));
    uint16_t ether_type = get_ethernet_type(base);
    if (ether_type == ETHERTYPE_IP ) {
        return base + ETHER_ADDR_LEN + ETHER_ADDR_LEN + ETHER_TYPE_LEN; // two times ETHER_ADDR_LEN (dst and src) plus ETHER_TYPE_LEN: 12 + 2
    } else if (ether_type == ETHERTYPE_VLAN ) {
        // VLAN tag
        ether_type = ntohs(*(uint16_t *) (base + ETHER_ADDR_LEN + ETHER_ADDR_LEN + ETHER_TYPE_LEN + ETHER_VLAN_ENCAP_LEN)); // 12 + 2 + 4
        if (ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6)  {
            return (base + ETHER_ADDR_LEN + ETHER_ADDR_LEN + ETHER_TYPE_LEN + ETHER_VLAN_ENCAP_LEN + ETHER_TYPE_LEN);   // 12 + 2 + 4 + 2
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        return base + ETHER_ADDR_LEN + ETHER_ADDR_LEN + ETHER_TYPE_LEN; // two times ETHER_ADDR_LEN (dst and src) plus ETHER_TYPE_LEN: 12 + 2
    }
    return NULL;
}
/**
 * @name   get_tcp_hdr
 * @note   locates the TCP protocol header in the ethernet packet right after IP header
 * @param  void *base: 
 * @retval pointer to the TCP header
 */
void *get_tcp_hdr(void *base) {
    assert(base);
    void *tcp = NULL, *ip = NULL;
    if ((ip = get_ip_hdr(base)) != NULL) {
        // get ethernet type: IPv4 or IPv6
        uint16_t ether_type = get_ethernet_type(base);
        if (ether_type == ETHERTYPE_IP) {
            tcp = (ip + sizeof(struct ip));
        } else if (ether_type == ETHERTYPE_IPV6) {
            tcp = (ip + sizeof(struct ip6_hdr));
        }
    }
    return tcp;
}
/**
 * @name   get_udp_hdr
 * @note   locates the UDP protocol header in the ethernet packet right after IP header
 * @param  void *base: 
 * @retval pointer to the UDP header
 */
void *get_udp_hdr(void *base) {
    assert(base);
    void *udp = NULL, *ip = NULL;
    struct ip *ipv4 = NULL;
    struct ip6_hdr *ipv6 = NULL;
    if (NULL != get_ip_hdr(base)) {
        if ((ip = get_ip_hdr(base)) != NULL) {
            // get ethernet type: IPv4 or IPv6
            uint16_t ether_type = get_ethernet_type(base);
            if (ether_type == ETHERTYPE_IP) {
                ipv4 = (struct ip *)ip;
                if (ipv4->ip_p == IPPROTO_UDP) {
                    udp = (ipv4 + sizeof(struct ip));
                }
            } else if (ether_type == ETHERTYPE_IPV6) {
                ipv6 = (struct ip6_hdr *)ip;
                if (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
                    udp = (ipv6 + sizeof(struct ip6_hdr));
                }
                udp = (ip + sizeof(struct ip6_hdr));
            }
        }
    }
    return udp;
}
/**
 * @name   get_payload
 * @note   returns the pointer of the payload and its size of the ethernet packet
 * @param  void *base - pointer to the ethernet packet
 * @param  size_t *size - pointer to the return value of the payload size
 * @retval None
 */
void *get_payload(void* base, size_t *size) {
    size_t len = 0;
    uint16_t ether_type = get_ethernet_type(base);
    void *payload = NULL, *ip;
    struct ip *ipv4 = NULL;
    struct ip6_hdr *ipv6 = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    if (ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6) {
        // normal ethernet header assumed
        if ((ip = get_ip_hdr(base)) != NULL) {
            ipv4 = (struct ip *)ip;
            if (ipv4->ip_p == IPPROTO_UDP) {
                int header_length = (ipv4->ip_hl * 4);
                len = ipv4->ip_len - header_length;
                payload = (ipv4 + header_length);
            }
        }
    } else if (ether_type == ETHERTYPE_VLAN) {
        // extended ethernet header assumed
        if ((ip = get_ip_hdr(base)) != NULL) {
            ipv6 = (struct ip6_hdr *)ip;
            int header_length = sizeof(struct ip6_hdr);
            len = ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen - header_length;
            payload = (ipv6 + ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        }
    }
    *size = len;
    return payload;
}
