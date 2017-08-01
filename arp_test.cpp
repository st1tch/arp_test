#include <pcap.h>
#include <memory.h>
#include <libnet.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hexdump.h"
#include "mymacip.h"

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_ETHER 0x0100	/* Ethernet 10Mbps 		   */
#define ARP_IP 0x0008		/* IPv4 				   */
#define ARP_HLEN 0x6		/* Mac addr length		   */	
#define ARP_PLEN 0x4		/* IPv4 addr length		   */
#define ARP_REQUEST 0x0100  /* req to resolve address */
#define ARP_REPLY 0x0200 	/* resp to previous request */
#define PACKET_SIZE 42		/* ethernet+arp = 12+28	   */
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

u_char tmp[PACKET_SIZE];

void make_arp_packet(uint8_t* sender_mac, in_addr_t sender_ip, uint8_t* target_mac, in_addr_t target_ip, int oper, int check){
	uint16_t test1 = ETHERTYPE_ARP;
	uint16_t test2 = ARP_ETHER;
	uint16_t test3 = ARP_IP;
	uint16_t test4 = ARP_HLEN;
	uint16_t test5 = ARP_PLEN;
	memset(tmp, 0, PACKET_SIZE);

	memcpy(tmp, target_mac, 6);			//ethernet dst mac addr
	memcpy(tmp+6, sender_mac, 6);		//ethernet src mac addr
	memcpy(tmp+12, &(test1), 2);	//ethernet type
	
	memcpy(tmp+14, &(test2), 2);		//arp hardware type
	memcpy(tmp+16, &(test3), 2);			//arp protocol type
	memcpy(tmp+18, &(test4), 1);		//arp hadreware addr length
	memcpy(tmp+19, &(test5), 1);		//arp protocol addr length
	memcpy(tmp+20, &(oper), 2);			//arp operation code
	memcpy(tmp+22, sender_mac, 6);		//arp sender hardware addr
	memcpy(tmp+28, &(sender_ip), 4);	//arp sender ip addr
	if (check)
		memcpy(tmp+32, target_mac, 6);		//arp target hardware addr
	memcpy(tmp+38, &(target_ip), 4);	//arp target ip addr
	hexdump(tmp, 48);
}

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

	struct in_addr my_ip;
	struct in_addr target_ip;
	struct in_addr sender_ip;

	char tmpIP[16];
	char tmppacket[42];

    if (argc != 4){
		printf("[!] Usage : %s [interface] [sender ip] [target ip]\n", argv[0]);
        return 0;
    }

    if((handle = pcap_open_live(argv[1], 2048, 1, 1024, errbuf)) == NULL){
        printf("[!] Device open Error!!!\n");
        perror(errbuf);
        exit(0);;
    }

	inet_pton(AF_INET, argv[2], &sender_ip.s_addr);
	inet_pton(AF_INET, argv[3], &target_ip.s_addr);
	get_mac(argv[1], (uint8_t*)mymac);
	my_ip = get_ip(argv[1]);

	printf("MY MAC -> ");
    for(i=0; i<6;i++)
        printf("%02X%s", mymac[i], (i==5 ? "\n" : ":"));

	sprintf(tmpIP, "%s", inet_ntoa(my_ip));
	printf("MY IP  -> %s\n", tmpIP);
	memset(tmpIP, 0, sizeof(inet_ntoa(my_ip)));

	sprintf(tmpIP, "%s", inet_ntoa(sender_ip));
	printf("SENDER IP  -> %s\n", tmpIP);
	memset(tmpIP, 0, sizeof(inet_ntoa(sender_ip)));

	sprintf(tmpIP, "%s", inet_ntoa(target_ip));
	printf("TARGET IP  -> %s\n", tmpIP);
	
	uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	make_arp_packet(mymac, my_ip.s_addr, broadcast, target_ip.s_addr, ARP_REQUEST, 0);
	if (pcap_sendpacket(handle, (u_char *)tmp, PACKET_SIZE) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        return -1;
    }
    
	if((handle = pcap_open_live(argv[1], 2048, 1, 1024, errbuf)) == NULL){
        printf("[!] Device open Error!!!\n");
        perror(errbuf);
        exit(0);;
    }
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
		
		//if (ntohs(arp_h->htype) == ARP_ETHER && ntohs(arp_h->ptype) == ARP_IP){
		if (ntohs(arp_h->htype) == ETHERTYPE_ARP){
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



