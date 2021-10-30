#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * HARDWARE TYPE : 這是指網路界面卡的種類﹐如果該值為 1﹐則表示為乙太網 ( Ethernet )。 
 * PROTOCOL TYPE : 這是指高階網路協定位址種類﹐如果該值為 0x0800﹐則表示為 IP 位址格式。 ARP : 0x0806
 * HLEN : 這是指硬體位址長度(單位為 byte)﹐乙太網的位址長度為 6 。 
 * PLEN : 這是指網路協定位址的長度(單位為 byte)﹐IP 協定位址長度為 4。 
 * OPERATION : 這是指封包類別﹐一共有四種﹕
        ARP Request
        ARP Reply
        RARP Request
        RARP Reply
 * SENDER HA : 這是指發送端的實體位址﹐如果是乙太網的話﹐將會是一個 6 byte 長度的乙太網位址。 
 * SENDER IP : 這是指發送端的 IP 位址﹐會是一個 4 byte 長度的 IP 位址。 
 * TARGET HA : 這是指目的端的實體位址﹐如果是乙太網的話﹐將會是一個 6 byte 長度的乙太網位址。 
 * TARGET IP : 這是指目的端的 IP 位址﹐會是一個 4 byte 長度的 IP 位址。 
 */


char mac[18];
char tar_mac[6] ;
char sen_mac[6] ;
//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void print_usage()
{
	printf("Format:\n");
	printf("1) ./arp -l -a\n");
	printf("2) ./arp -l <filter_ip_address>\n");
	printf("3) ./arp -q <query_ip_address>\n");
	printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
}
//if_ether.h
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_hrd = htons(type);
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_pro = htons(type);
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
	packet->arp_op = htons(code);
}
void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
	//struct ether_addr src_addr;
	//ether_aton_r(address, &src_addr);
	memcpy(packet->arp_sha, address, packet->arp_hln);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	in_addr_t src_ip;
	src_ip = inet_addr(address);
	memcpy(packet->arp_spa, &src_ip, packet->arp_pln);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	//struct ether_addr dst_addr;
	//ether_aton_r(address, &dst_addr);
	memcpy(packet->arp_tha, address, packet->arp_hln);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	in_addr_t dst_ip;
	dst_ip = inet_addr(address);
	memcpy(packet->arp_tpa, &dst_ip, packet->arp_pln);
}



char* get_target_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	struct in_addr target_addr;
	memcpy(&target_addr, packet->arp_tpa, 4);
	return inet_ntoa(target_addr);
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	struct in_addr sender_addr;
	memcpy(&sender_addr, packet->arp_spa, 4);
	return inet_ntoa(sender_addr);
}



char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	//struct ether_addr sender_mac;
	//memcpy(&sender_mac, packet->arp_sha, 6);

sprintf(sen_mac,"%02x:%02x:%02x:%02x:%02x:%02x",packet->arp_sha[0],packet->arp_sha[1],packet->arp_sha[2],packet->arp_sha[3],packet->arp_sha[4],packet->arp_sha[5]);
	return sen_mac;

    //return ether_ntoa(sender_mac);

	//ether_ntoa_r(&sender_mac, mac);
	//return mac;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	//struct ether_addr target_mac;
	//memcpy(&target_mac, packet->arp_tha, 6);
	sprintf(tar_mac,"%02x:%02x:%02x:%02x:%02x:%02x",packet->arp_tha[0],packet->arp_tha[1],packet->arp_tha[2],packet->arp_tha[3],packet->arp_tha[4],packet->arp_tha[5]);
	return tar_mac;

	
	//return ether_ntoa(target_mac);

	//ether_ntoa_r(&target_mac, mac);
	//return mac;
}
