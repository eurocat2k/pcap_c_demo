#ifndef __CAP_H_C0DB364B_2050_4639_8267_9D688869C3A7
#define __CAP_H_C0DB364B_2050_4639_8267_9D688869C3A7

#include <unistd.h>
#include <sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header

#ifndef SIZE_ETHERNET
#define SIZE_ETHERNET 14
#endif

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

#ifndef CHAR_BITS
#define CHAR_BITS (8)
#endif

#ifndef ETHER_TYPE
#define ETHER_TYPE(type) (unsigned short)(((type) >> (CHAR_BITS)) | ((type) << (CHAR_BITS)))
#endif

typedef struct sniff_ipv6 {
  unsigned char *pkt;
  int pkt_len;
  char *next_segment;
  char *final;
  int final_type;
  unsigned int version;         // :4;
  unsigned char sclass;
  unsigned int label;           // :20;
  unsigned int length;          // :16;
  unsigned char next;
  unsigned char ttl;
  unsigned char src[16];
  unsigned char dst[16];
  unsigned char *final_dst;
  unsigned char *original_src;
} sniff_ipv6_t, *sniff_ipv6_ptr;

struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#ifndef IP_HL
#define IP_HL(ip)               (((ip)->ip_hl) & 0x0f)
#endif  //!IP_HL

#ifndef IP_V
#define IP_V(ip)                (((ip)->ip_v) >> 4)
#endif  //!IP_V

#ifndef IP_TOTAL
#define IP_TOTAL(v) (unsigned short)(((v)>>8) | ((v)<<8))
#endif // !IP_TOTAL

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
#ifndef TH_FLAGS
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#endif
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

#endif /* __CAP_H_C0DB364B_2050_4639_8267_9D688869C3A7 */
