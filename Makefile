arp_test : arp_test.cpp
	g++ -o arp_test arp_test.cpp -lpcap

clean :
	rm arp_test
