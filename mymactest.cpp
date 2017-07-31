#include <pcap.h>
#include <libnet.h>
#include "hexdump.h"

int main(int argc, char *argv[]){
	struct ifreq ifr;
	int sock;
	char chMAC[6];

	sock=socket(AF_INET,SOCK_DGRAM, IPPROTO_IP);
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy( ifr.ifr_name, argv[1] );

	if (ioctl( sock, SIOCGIFHWADDR, &ifr ) != 0) {
		return -1;
	}

	close(sock);
	memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6);
	hexdump(chMAC, 6);

	return 0;
}
