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
#include <pthread.h> //import pthread library


pcap_t *handle; /* Session handle */
pcap_if_t *alldevs; /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
struct bpf_program fp; /* The compiled filter */
char filter[]=""; /* The filter expression */
bpf_u_int32 mask; /* Our netmask */
bpf_u_int32 net; /* Our IP */
struct pcap_pkthdr *header; /* The header that pcap gives us */
const u_char *packet; /* The actual packet */
struct in_addr addr; /*address */
int enter;
int inum, i=0;
pcap_if_t *dev;




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


/*thread Data type*/
pthread_t thread,write;




void *number(){
        scanf("%d",&enter);
        if(enter==1){
	printf("dhcp discover: %d\n",discover);
	printf("dhcp offer: %d\n",offer);
	printf("dhcp request: %d\n",request); 
	printf("dhcp ack: %d\n", ack);
	
	}
}
	





void *dcount(){
	
        eth=(struct sniff_ethernet*)(packet);

        if(ntohs(eth->ether_type)==ETHERTYPE_IP){
         ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
         size_ip=IP_HL(ip)*4;
           if(ip->ip_p==IPPROTO_UDP){
                udp=(struct dhcp_header*)(packet+size_ip+SIZE_ETHERNET);
              if(ntohs(udp->uh_sport)==DHCPV4_CLIENT_PORT||ntohs(udp->uh_sport)==DHCPV4_SERVER_PORT){
                if(ntohs(udp->uh_dport)==DHCPV4_CLIENT_PORT||ntohs(udp->uh_dport)==DHCPV4_SERVER_PORT){
                  dhcp=(struct dhcp_header*)(packet+size_ip+SIZE_ETHERNET+SIZE_UDP);
                  /*print dhcp packet count*/
                  detection(ip,udp,dhcp);

/* check dhcp message option count

                  printf("============= DHCP Count ===========\n");
                  printf("DHCP Discover: %d\n",discover);
                  printf("DHCP Offer: %d\n",offer);
                  printf("DHCP Request: %d\n",request);
                  printf("DHCP Ack: %d\n", ack);  

*/
	

        }
        }
        }
        }
  
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



        if(eth_type == 0x0800) {
          if(ip->ip_p == IPPROTO_UDP){
                if(uh_sport==68 || uh_sport==67){
                 if(uh_dport==67 || uh_dport==68){


        //dhcp message option
        struct dhcpv4_message *req = dhcp;
        uint8_t reqmsg = 0; //setting initial price

        struct dhcpv4_option *opt;
        uint8_t *start = &req->options[4];
        uint8_t *end = ((uint8_t*)dhcp) + udp->uh_ulen;//(uint8_t*)dhcp=udp len



        dhcpv4_for_each_option(start, end, opt){
        if(opt->type)
          // printf("DHCP Option Number [%d] len[%d]", opt->type, opt->len);
        if (opt->type == DHCPV4_OPT_MESSAGE && opt->len == 1){
            reqmsg = opt->data[0];
           // printf("data: %d\n",reqmsg);

                if(reqmsg==1){ discover++; }
                if(reqmsg==2) { offer++; }
                if(reqmsg==3){ request++; }
                if(reqmsg==5){ ack++; }


        }
        }
                }
           }
        }
     }

}




/* main */
int main(void) {

          if(pcap_findalldevs(&alldevs, errbuf) == -1) { 

    printf("Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);

  }

  for(dev=alldevs; dev; dev=dev->next) { 

    printf("%d. %s", ++i, dev->name);
    if (dev->description)
      printf(" (%s)\n", dev->description);
    else
      printf(" (No description available)\n");
  }

  if(i==0) {  

    printf("\nNo interfaces found! Make sure LiPcap is installed.\n");
    //return -1;
  }

  printf("Enter the interface number (1-%d):",i);
  scanf("%d", &inum);

  if(inum < 1 || inum > i) { 
    printf("\nAdapter number out of range.\n");
    pcap_freealldevs(alldevs);  
    return -1;
  }

  for(dev=alldevs, i=0; i< inum-1 ;dev=dev->next, i++);   


  if((handle= pcap_open_live(dev->name, 65536,   1,  0,  errbuf  )) == NULL) {     printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_compile(handle, &fp,filter,0, net) == -1 )  { 


    printf("\nUnable to compile the packet filter. Check the syntax.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_setfilter(handle, &fp)==-1)  {  
    printf("\nError setting the filter.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", dev->description);  
  pcap_freealldevs(alldevs);   

        printf("detects packets.\n");
	printf("If you want to check the statistics, enter 1 ");	
        while(pcap_next_ex(handle, &header, &packet) == 1) {

	
	pthread_create(&thread, NULL,dcount,NULL);
	usleep(100);
	pthread_create(&write, NULL, number,NULL);

	pthread_detach(thread);

	if(enter==1) { return 0;}

        }


	return 0;

}



       
