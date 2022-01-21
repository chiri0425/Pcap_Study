#include <stdio.h>
#include <pcap.h> // Import PCAP Library
#include <arpa/inet.h> // inet_ntoa etc
#include <netinet/in.h> // in_addr etc
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // int8_t etc
#include <sys/types.h>
#include <sys/socket.h>


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


#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};





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


/* udp header */
struct udp_header {
        u_short uh_sport;  /* source port */
        u_short uh_dport;        /* destination port */
        u_short uh_ulen;         /* udp length */
        u_short uh_sum;		/*udp checksum */
};

/* dhcp header */
struct dhcp_header {
    u_char		dp_op;		/* packet opcode type */
    u_char		dp_htype;	/* hardware addr type */
    u_char		dp_hlen;	/* hardware addr length */
    u_char		dp_hops;	/* gateway hops */
    u_int		dp_xid;		/* transaction ID */
    u_short		dp_secs;	/* seconds since boot began */	
    u_short		dp_flags;	/* flags */
    struct in_addr	dp_ciaddr;	/* client IP address */
    struct in_addr	dp_yiaddr;	/* 'your' IP address */
    struct in_addr	dp_siaddr;	/* server IP address */
    struct in_addr	dp_giaddr;	/* gateway IP address */
    u_char		dp_chaddr[16];	/* client hardware address */
    u_char		dp_sname[64];	/* server host name */
    u_char		dp_file[128];	/* boot file name */
    u_char		dp_options[0];	/* variable-length options field */
};

/* dhcp message types */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7



struct sniff_ip *ip; /* The IP header */
u_int size_ip;
struct udp_header *udp; /*The UDP header */



/* main */
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
               
	 ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
	 size_ip=IP_HL(ip)*4;
	 udp=(struct udp_header*)(packet+size_ip+SIZE_ETHERNET);
	 detection(ip,udp);


        }
	return 0;
}


void detection(struct sniff_ip *ip,struct udp_header *udp){

	struct sniff_ethernet *eth;
	eth=(struct sniff_ethernet *)packet;
	u_short eth_type;
	u_short uh_sport;
	uh_sport=ntohs(udp->uh_sport);
	eth_type=ntohs(eth->ether_type);
	size_ip = IP_HL(ip)*4;
	if(eth_type == 0x0800) {
	  if(ip->ip_p == IPPROTO_UDP){
		if(uh_sport==17500){
	printf("\n========== UDP Packet ==========\n");
        printf("\nIP Source Address: %s\n", inet_ntoa(ip->ip_src));
        printf("IP Destination Address: %s\n", inet_ntoa(ip->ip_dst));
	printf("Protocol: %d\n",ip->ip_p);	
	printf("Source Port: %d\n", ntohs(udp->uh_sport));
	printf("Destination Port: %d\n", ntohs(udp->uh_dport));
     	}
	}
    }
}
