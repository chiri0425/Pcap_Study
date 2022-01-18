#include <stdio.h>
#include <pcap.h> // Import PCAP Library
#include <arpa/inet.h> // inet_ntoa etc
#include <netinet/in.h> // in_addr etc
#include <stdlib.h>
#include <string.h>

pcap_t *handle; /* Session handle */
char *dev ; /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
struct bpf_program fp; /* The compiled filter */
char *filter_exp; /* The filter expression */
bpf_u_int32 mask; /* Our netmask */
bpf_u_int32 net; /* Our IP */
struct pcap_pkthdr *header; /* The header that pcap gives us */
const unsigned char *packet; /* The actual packet */
//struct in_addr addr; /*address */



/* Ethernet addresses are 6 bytes */
struct ether_addr {

  unsigned char mac_add[6];
  
};

struct ether_header {

    struct ether_addr etherdst_mac; 
    struct ether_addr ethersed_mac; 
    unsigned short ether_type; // ARP request or ARP reply
};


#pragma pack(push, 2)
struct arp_header {

    unsigned short Hardw_type;
    unsigned short Prtoc_type;
    unsigned char Hardwadd_len;    unsigned char Prtocadd_len;
    unsigned short Op_code;     /*arp request or arp reply*/
    struct ether_addr Arpsed_mac;
    struct in_addr Arpsed_ip;
    struct ether_addr Arptar_mac;
    struct in_addr Arptar_ip;

};  
#pragma pack(pop)



void detect_ethernet(const unsigned char *packet);
void arp_info(const unsigned char *packet);

 
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
                detect_ethernet(packet);
		packet += 14;
        	arp_info(packet);

	}
	return 0;
 }

void detect_ethernet(const unsigned char *packet){
    struct ether_header *eth; //ehternet header
    eth = (struct ether_header *)packet;  // ehternet packet
    unsigned short eth_type;
    eth_type= ntohs(eth->ether_type);  //ehternet type

    if (eth_type == 0x0806) {// detection ARP packet
        printf("\n====== ARP packet ======\n");
        printf("\nSrc MAC : ");
        for (int i=0; i<=5; i++)
            printf("%02x ",eth->ethersed_mac.mac_add[i]);
        printf("\nDst MAC : ");
        for (int i=0; i<=5; i++)
            printf("%02x ",eth->etherdst_mac.mac_add[i]);
        printf("\n");
    }
}

/* print arp packet information */
void arp_info(const unsigned char *packet) {

    struct arp_header *arprqip;
    struct arp_header *arprpip;
    struct arp_header *arpmac;
    struct arp_header *arpop;
    arprqip = (struct arp_header *)packet;  
    arprpip = (struct arp_header *)packet;
    arpmac = (struct arp_header *)packet;
    arpop = (struct arp_header *)packet;
    unsigned short Arpopcode = ntohs(arpop -> Op_code);  // Op_code define

    if (Arpopcode == 0x0001) {  // request = 1
        printf(" ******* request ******* \n");
        printf(" Sender IP : %s\n ", inet_ntoa(arprqip -> Arpsed_ip)); 
        printf("Target IP : %s\n ", inet_ntoa(arprqip -> Arptar_ip));
        printf("\n");
    }
    
    if (Arpopcode == 0x0002) {  // reply = 2
        printf(" ********  reply  ******** \n");
        printf(" Sender IP  : %s\n ", inet_ntoa(arprpip -> Arpsed_ip));
        printf("Sender MAC : ");
        for (int i=0; i <=5; i ++) printf("%02x ",arpmac -> Arpsed_mac.mac_add[i]);
        printf("\n");
        printf(" Target IP  : %s\n ", inet_ntoa(arprpip -> Arptar_ip));
        printf("Target MAC : ");
        for (int i=0; i <=5; i ++) printf("%02x ",arpmac -> Arptar_mac.mac_add[i]);
        printf("\n");

    }

}
