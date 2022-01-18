
#include <stdio.h>
#include <pcap.h> // Import PCAP Library
#include <arpa/inet.h> // inet_ntoa etc
#include <netinet/in.h> // in_addr etc
#include <stdlib.h>
#include <string.h>



pcap_t *handle; /* Session handle */
pcap_if_t *alldevs; /* all device */
//char *dev ; /* The device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
struct bpf_program fp; /* The compiled filter */
char filter[] = "";  /* The filter expression */
bpf_u_int32 mask; /* Our netmask */
bpf_u_int32 net; /* Our IP */
struct pcap_pkthdr *header; /* The header that pcap gives us */
const u_char *packet; /* The actual packet */
//struct in_addr addr; /*address */
int inum, i=0;
pcap_if_t *dev;


#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct ether_header {

    u_char etherdst_mac[ETHER_ADDR_LEN]; 
    u_char ethersed_mac[ETHER_ADDR_LEN]; 
    unsigned short ether_type; // ARP?IP?

};


#pragma pack(push, 2)  /* Arrange the size of the structure.(2byte) */
struct arp_header {

    unsigned short Hardw_type;
    unsigned short Prtoc_type;
    unsigned char Hardwadd_len;
    unsigned char Prtocadd_len;
    unsigned short Op_code;      
    u_char Arpsed_mac[ETHER_ADDR_LEN];
    struct in_addr Arpsed_ip;
    u_char Arptar_mac[ETHER_ADDR_LEN];
    struct in_addr Arptar_ip;

};  
#pragma pack(pop)


void detect_ethernet(const unsigned char *packet);
void arp_info(const unsigned char *packet);

/* ethernet headers are always exactly 14 bytes */

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

        printf("Detects packets.\n");
        while(pcap_next_ex(handle, &header, &packet) == 1) {
        	detect_ethernet(packet);
        	packet += 14;
        	arp_info(packet);
        }
    
  return 0;

}

/* print ethernet header */
void detect_ethernet(const unsigned char *packet) {  

    struct ether_header *eth; //ethernet header
    eth = (struct ether_header *)packet;  
    unsigned short eth_type;
    eth_type= ntohs(eth->ether_type);
    if (eth_type == 0x0806) {//catch ARP packet
        printf("\n====== ARP packet ======\n");
        printf("\nSrc MAC : ");
        for (int i=0; i<ETHER_ADDR_LEN; i++)
            printf("%02x ",eth->ethersed_mac[i]);
        printf("\nDst MAC : ");
        for (int i=0;i<ETHER_ADDR_LEN; i++)
            printf("%02x ",eth->etherdst_mac[i]);
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
    unsigned short Arpopcode = ntohs(arpop -> Op_code);  /* Op_code define */

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
        for (int i=0; i<ETHER_ADDR_LEN; i++) printf("%02x ",arpmac -> Arpsed_mac[i]);
        printf("\n");
        printf(" Target IP  : %s\n ", inet_ntoa(arprpip -> Arptar_ip));
        printf("Target MAC : ");
        for (int i=0; i<ETHER_ADDR_LEN; i ++) printf("%02x ",arpmac -> Arptar_mac[i]);
        printf("\n");

    }

}

