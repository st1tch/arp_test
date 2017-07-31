
void get_mac(char *dev, uint8_t chMAC[6]){
	struct ifreq ifr;
	int sock;

	sock=socket(AF_INET,SOCK_DGRAM, IPPROTO_IP);
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, dev );

	if (ioctl( sock, SIOCGIFHWADDR, &ifr ) != 0) {
		printf("Error!\n");
		exit(2);
	}
	close(sock);

	memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6);
}

struct in_addr get_ip(char *dev){
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0){
        exit(2);
    }
    close(sock);
    return ((struct sockaddr_in *) &(ifr.ifr_addr))->sin_addr;
}
