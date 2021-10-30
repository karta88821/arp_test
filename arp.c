#include "arp.h"
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define IP_ADDR_LEN 4
#define ETH_ALEN 6

void print_usage()
{
	printf("Format:\n");
	printf("(1) ./arp -l -a\n");
	printf("(2) ./arp -l <filter_ip_address>\n");
	printf("(3) ./arp -q <query_ip_address>\n");
	printf("(4) ./arp <fake_mac_address> <target_ip_address>\n");	
}
bool isIP(char *str)
{
	char ip[4];
	return (sscanf(str, "%[0-9].%[0-9].%[0-9].%[0-9]", &ip[0], &ip[1], &ip[2], &ip[3]) == 4) ? true : false;	
}
bool isMAC(char *str)
{
	char mac[6];
	return (sscanf(str, "%[a-zA-Z0-9]:%[a-zA-Z0-9]:%[a-zA-Z0-9]:%[a-zA-Z0-9]:%[a-zA-Z0-9]:%[a-zA-Z0-9]", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) ? true : false;	
}


//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_hrd = type;
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_pro = type;
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->arp_op = code;
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_sha, address, ETH_ALEN);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	struct in_addr src_in_addr;
	inet_pton(AF_INET, address, &src_in_addr);
	memcpy(packet->arp_spa, &src_in_addr, IP_ADDR_LEN);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tha, address, ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	struct in_addr dst_in_addr;
	inet_pton(AF_INET, address, &dst_in_addr);
	memcpy(packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	char *tpa = (char*)malloc(sizeof(char)*16);
	sprintf(tpa, "%u.%u.%u.%u", packet->arp_tpa[0], packet->arp_tpa[1], packet->arp_tpa[2], packet->arp_tpa[3]);
	return tpa;
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	char *spa = (char*)malloc(sizeof(char)*16);
	sprintf(spa, "%u.%u.%u.%u", packet->arp_spa[0], packet->arp_spa[1], packet->arp_spa[2], packet->arp_spa[3]);
	return spa;
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	char *sha = (char*)malloc(sizeof(char)*18);
	sprintf(sha, "%02x:%02x:%02x:%02x:%02x:%02x", packet->arp_sha[0], packet->arp_sha[1], packet->arp_sha[2], packet->arp_sha[3], packet->arp_sha[4], packet->arp_sha[5]);
	return sha;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	char *tha = (char*)malloc(sizeof(char)*18);
	sprintf(tha, "%02x:%02x:%02x:%02x:%02x:%02x", packet->arp_tha[0], packet->arp_tha[1], packet->arp_tha[2], packet->arp_tha[3], packet->arp_tha[4], packet->arp_tha[5]);
	return tha;
}
