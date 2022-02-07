#include <stdio.h>
#include <pcap.h> // Import PCAP Library
#include <arpa/inet.h> // inet_ntoa etc
#include <netinet/in.h> // in_addr etc
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // int8_t etc
#include <sys/types.h>
#include <sys/socket.h>
#include "dhcpv4.h" /*dhcp header file*/
#include <syslog.h> // log



pcap_t *handle; /* Session handle */
char dev[]="enp0s3.4000"; /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
struct bpf_program fp; /* The compiled filter */
char *filter_exp; /* The filter expression */
bpf_u_int32 mask; /* Our netmask */
bpf_u_int32 net; /* Our IP */
struct pcap_pkthdr *header; /* The header that pcap gives us */
const u_char *packet; /* The actual packet */
struct in_addr addr; /*address */
//char *enter;
int enter;

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6


/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */


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



#define SIZE_UDP 8
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
    u_char		dp_options[312];	/* variable-length options field */
};


#define MESSAGE_TYPE_DHCP   53

/* dhcp message types */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7




struct sniff_ip *ip; // The IP header
u_int size_ip;
struct udp_header *udp; //The UDP header
struct dhcp_header *dhcp; //The DHCO header
struct sniff_ethernet *eth; //The Ether header



/* dhcp option count*/
static int discover;
static int offer;
static int request;
static int ack;




/* main */
int main(void) {

	/* Define the device */
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
	 eth=(struct sniff_ethernet*)(packet);

	if(ntohs(eth->ether_type)==ETHERTYPE_IP){
	 ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
	 size_ip=IP_HL(ip)*4;
	   if(ip->ip_p==IPPROTO_UDP){
		udp=(struct dhcp_header*)(packet+size_ip+SIZE_ETHERNET);
	      if(ntohs(udp->uh_sport)==DHCPV4_CLIENT_PORT||ntohs(udp->uh_sport)==DHCPV4_SERVER_PORT){
		if(ntohs(udp->uh_dport)==DHCPV4_CLIENT_PORT||ntohs(udp->uh_dport)==DHCPV4_SERVER_PORT){
		  dhcp=(struct dhcp_header*)(packet+size_ip+SIZE_ETHERNET+SIZE_UDP);
		  	
		  detection(ip,udp,dhcp);
		  printf("============= DHCP Count ===========\n");
		  printf("DHCP Discover: %d\n",discover);
		  printf("DHCP Offer: %d\n",offer);
		  printf("DHCP Request: %d\n",request);
		  printf("DHCP Ack: %d\n", ack);
			
		  //  scanf("%d",&enter);
		   // if(enter==1){printf("dhcp request: %d\n",request); return 0;}							   
	}
	}
	}
	}
	else{continue; }
	continue; 

        }

	return 0;
}


void detection(struct sniff_ip *ip,struct udp_header *udp,struct dhcp_header *dhcp){

	struct sniff_ethernet *eth;
	eth=(struct sniff_ethernet *)packet;
	u_short eth_type;
	u_short uh_sport;
	u_short uh_dport;
	u_char dp_options;
	uh_dport=ntohs(udp->uh_dport);
	uh_sport=ntohs(udp->uh_sport);
	eth_type=ntohs(eth->ether_type);
	size_ip = IP_HL(ip)*4;
//	u_char dp_op;
//	struct dhcpv4_option *	
	
	if(eth_type == 0x0800) {
	  if(ip->ip_p == IPPROTO_UDP){
		if(uh_sport==68 || uh_sport==67){
		 if(uh_dport==67 || uh_dport==68){				
/*	printf("\n========== IP & UDP Packet ==========\n");
        printf("\nIP Source Address: %s\n", inet_ntoa(ip->ip_src));
        printf("IP Destination Address: %s\n", inet_ntoa(ip->ip_dst));
	printf("Protocol: %d\n",ip->ip_p);	
	printf("Source Port: %d\n", ntohs(udp->uh_sport));
	printf("Destination Port: %d\n", ntohs(udp->uh_dport));
	printf("\n============ DHCP Message =======\n");
	printf("Client IP Address: %s\n",inet_ntoa(dhcp->dp_ciaddr));
	printf("Your IP Address: %s\n", inet_ntoa(dhcp->dp_yiaddr));
	printf("Server IP Address: %s\n", inet_ntoa(dhcp->dp_siaddr));
	printf("Gateway IP Address: %s\n", inet_ntoa(dhcp->dp_giaddr));	
*/

	struct dhcpv4_message *req = dhcp;
	uint8_t reqmsg = 0; //setting initial price

    	struct dhcpv4_option *opt;
	uint8_t *start = &req->options[4];
    	uint8_t *end = ((uint8_t*)dhcp) + udp->uh_ulen; /*(uint8_t*)dhcp=udp len*/
	


    	dhcpv4_for_each_option(start, end, opt){ 
        if(opt->type)
          // printf("DHCP Option Number [%d] len[%d]", opt->type, opt->len);
	if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1){
            reqmsg = opt->data[0];
	   // printf("data: %d\n",reqmsg);
	    
		if(reqmsg==1){/* printf(" discover ");*/ discover++;/*printf("count: %d",discover);*/ }
		if(reqmsg==2) {/* printf(" offer ");*/ offer++;/* printf("count: %d",offer);*/ }
		if(reqmsg==3){/*	printf(" reqeust  ");*/ request++;/* printf("count: %d", request);*/ }
		if(reqmsg==5){/* printf(" ack ");*/ ack++;/* printf("count: %d", ack);*/ }

	
	
	}
	}
      		}
       	   }   	
	}
     }

}
