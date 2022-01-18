#include <stdio.h>
#include <pcap.h> // Import PCAP Library
#include <arpa/inet.h> // inet_ntoa etc
#include <netinet/in.h> // in_addr etc


pcap_t *handle; /* Session handle */
char *dev ; /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
struct bpf_program fp; /* The compiled filter */
char *filter_exp; /* The filter expression */
bpf_u_int32 mask; /* Our netmask */
bpf_u_int32 net; /* Our IP */
struct pcap_pkthdr *header; /* The header that pcap gives us */
const u_char *packet; /* The actual packet */
struct in_addr addr; /*address */



/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6 

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* Ethernet protocol ID's */
#define	ETHERTYPE_PUP		0x0200          /* Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/* Sprite */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
#define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/* IPX */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */


/* IP header */
struct sniff_ip {
        u_char ip_vhl; /* version << 4 | header length >> 2 */
        u_char ip_tos;  /* type of service */
        u_short ip_len; /* total length */
        u_short ip_id;  /* identification */
        u_short ip_off; /* fragment offset field */
        #define IP_RF 0x8000 /* reserved fragment flag */
        #define IP_DF 0x4000 /* don't fragment flag */
        #define IP_MF 0x2000  /* more fragments flag */
        #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
        u_char ip_ttl; /* time to live */
        u_char ip_p; /* protocol */
        u_short ip_sum; /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport; /* source port */
        u_short th_dport; /* destination port */
        tcp_seq th_seq; /* sequence number */
        tcp_seq th_ack; /* acknowledgement number */
        u_char th_offx2; /* data offset, rsvd */
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win; /* window */
        u_short th_sum; /* checksum */
        u_short th_urp; /* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

struct sniff_ethernet *ethernet; /* The ethernet header */
struct sniff_ip *ip; /* The IP header */
struct sniff_tcp *tcp; /* The TCP header */
char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

void detection() {
        printf("=====================================================\n");
        int i; /*, payload_len;*/
	
	/* print ethernet */
        ethernet = (struct sniff_ethernet*)(packet);
        /* MAC Source Address */
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_shost[i]);
        }
	printf("(%dbyte)", ETHER_ADDR_LEN);
        /* MAC Destination Address */
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
	printf("(%dbyte)", ETHER_ADDR_LEN);
	//printf(" %d ",ether_type);
	/* print ip */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        printf("\nIP Source Address: %s\n", inet_ntoa(ip->ip_src));
        printf("IP Destination Address: %s\n", inet_ntoa(ip->ip_dst));
	
	/* print tcp */
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        printf("Source Port: %d\n", ntohs(tcp->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp->th_dport));
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        /*payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
        if(payload_len == 0) printf("ﾆ菎ﾌｷﾎｵ�ｵ･ﾀﾌﾅﾍｰ｡ ｾﾀｴﾏｴﾙ.");
        else {
                printf("< ﾆ菎ﾌｷﾎｵ�ｵ･ﾀﾌﾅﾍ >\n");
                for(int i = 1; i < payload_len; i++) {
                        printf("%02x ", payload[i - 1]);
                        if(i % 8 == 0) printf("  ");
                        if(i % 16 == 0) printf("\n");
                }
        }*/
        printf("\n=============================================\n");
}

int main(void) {

	/* Define the device */
       dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                printf("Couldn't find default device.\n");
                return 0;
        }
        /* Find the properties for the device */
        printf("My network device: %s\n", dev);
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                printf("Couldn't get netmask for device. \n");
                return 0;
        }
        addr.s_addr = net;
        printf("My IP Address: %s\n", inet_ntoa(addr));
        addr.s_addr = mask;
        printf("My Subnetmask: %s\n", inet_ntoa(addr));
        
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        if (handle == NULL) {
                printf("Couldn't open device.\n");
                return 0;
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("Couldn't parse filter. \n");
                return 0;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf("Couldn't install filter.\n");
                return 0;
        }
        printf("Detects packets.\n");
        while(pcap_next_ex(handle, &header, &packet) == 1) {
                detection();
        }
	return 0;
}
