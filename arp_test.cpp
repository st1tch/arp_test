#include <pcap.h>
#include <memory.h>
#include <libnet.h>
#include <stdint.h>
#include "hexdump.h"
#include "mymacip.h"

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_ETHER 1		/* Ethernet 10Mbps 		   */
#define ARP_IP 0x8000	/* IPv4 				   */
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 

int main(int argc, char *argv[])
{
    const uint8_t *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    pcap_t *handle;
    uint8_t res;
	uint8_t mymac[6];
	int i;

	libnet_ethernet_hdr *eth_h;
	arphdr_t *arp_h;
	int eth_len = sizeof(*eth_h);
	int arp_len = sizeof(*arp_h);
	struct in_addr myip;

	char chIP[16];

    if (argc != 4){
		printf("[!] Usage : %s [interface] [sender ip] [target ip]\n", argv[0]);
        return 0;
    }

    if((handle = pcap_open_live(argv[1], 2048, 1, 1024, errbuf)) == NULL){
        printf("[!] Device open Error!!!\n");
        perror(errbuf);
        exit(0);;
    }

	get_mac(argv[1], mymac);
	myip = get_ip(argv[1]);

	printf("MY MAC -> ");
    for(i=0; i<6;i++)
        printf("%02X%s", mymac[i], (i==5 ? "" : ":"));

	sprintf(chIP, "%s", inet_ntoa(myip));
	printf("\nMY IP  -> %s\n", chIP);

    while(1){
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0 || packet == NULL)
            continue;
        if (res == -1 || res == -2){
            printf("[!] EXIT process\n");
            break;
        }

		eth_h = (libnet_ethernet_hdr *) packet;
		arp_h = (arphdr_t *) (packet+eth_len);
		
		if (ntohs(arp_h->htype) == ARP_ETHER && ntohs(arp_h->ptype) == ARP_IP){
			printf("Hardware type: %s\n", (ntohs(arp_h->htype) == ARP_ETHER) ? "Ethernet" : "Unknown"); 
			printf("Protocol type: %s\n", (ntohs(arp_h->ptype) == ARP_IP) ? "IPv4" : "Unknown"); 
			printf("Operation: %s\n", (ntohs(arp_h->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 

			printf("Sender MAC: "); 

			for(i=0; i<6;i++)
				printf("%02X:", arp_h->sha[i]); 

			printf("\nSender IP: "); 

			for(i=0; i<4;i++)
				printf("%d.", arp_h->spa[i]); 

			printf("\nTarget MAC: "); 

			for(i=0; i<6;i++)
				printf("%02X:", arp_h->tha[i]); 

			printf("\nTarget IP: "); 

			for(i=0; i<4; i++)
				printf("%d.", arp_h->tpa[i]); 
			
			printf("\n"); 	
		}
    }

    return 0;
}



