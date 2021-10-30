#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

#define DEVICE_NAME "h1-eth0"
#define BUFFER_SIZE 1024

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

//int main(void)
int main(int argc, char *argv[])
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	
	int recv_size, send_size;
	struct arp_packet arp_pkt;    //arp.h
	struct arp_packet recv_packet;//arp.h
	char buffer[BUFFER_SIZE];
	int flag = 0, ifindex ;
	unsigned char mac_addr[6];
	const unsigned char ether_broadcast_addr[]={0xff,0xff,0xff,0xff,0xff,0xff};		//broadcast

//unsigned char fake_address[6];
	
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("ERROR : You must be root to use this tool!\n");
		//perror("open recv socket error");
        exit(1);
	}
	
	/*-----     prevent silly input     -----*/
	
	//input is ./arp -l -a
	if(strcmp(argv[1], "-l") == 0 && strcmp(argv[2], "-a") == 0 && argc == 3)
	{			
		flag = 1;
	}
	
	//input is ./arp -a <ip>
	else if(strcmp(argv[1], "-l") == 0 && argc == 3)		
	{
		flag = 2;
//in.h
		struct in_addr addr;			//check ip format
		int correct = inet_pton(AF_INET, argv[2], &(addr));//成功時傳回 1，有錯誤時傳回 -1；若輸入的 IP address 不正確，則傳回 0。

		if (correct <= 0)
			flag = 0;
	}
	//input is ./arp -q <ip>
	else if(strcmp(argv[1], "-q") == 0 && argc == 3)			
	{
		flag = 3;
		struct in_addr addr;			//check ip format
//inet_pton() 也會在 af 參數代入一個 address family（不是 AF_INET 就是 AF_INET6）、src 參數是指向可列印格式的 IP address 字串、最後的 dst 參數指向要儲存結果的地方，這可能是 struct in_addr 或 struct in6_addr
		int correct = inet_pton(AF_INET, argv[2], &(addr));//字串格式的 IP address 封裝到 struct sockaddr_in 
		if (correct <= 0)
			flag = 0;
	}
	//input is ./arp <mac> <ip>
	else if (argc == 3)			
	{
		flag = 4;
		int count = 0 , i = 0;
		while( i < strlen(argv[1])) 				//check mac format
		{
				if(argv[1][2] != ':' || argv[1][5] != ':' || argv[1][8] != ':' || argv[1][11] != ':' || argv[1][14] != ':')
					flag = 0;
				else if ((i !=2 && i!=5 && i!=8 && i!=11 && i!=14) && !((argv[1][i] >= '0' && argv[1][i] <= '9') || (argv[1][i] >= 'a' && argv[1][i] <= 'f'))) 
					flag = 0;
				
				i++;
		}
		struct in_addr addr;					//check ip format
		int correct = inet_pton(AF_INET, argv[2], &(addr.s_addr));
		if (correct <= 0)
			flag = 0;
	}
	
	if(flag == 0)
	{
		print_usage();
		exit(1);
	}
	/*-----     prevent silly input end      -----*/
	
	
	printf("[ ARP sniffer and spoof program ]\n");
	printf("### ARP sniffer mode ###\n");
	
	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	 if(flag == 1 || flag == 2)
	{		
		while(1)
		{
			if((recv_size = recvfrom(sockfd_recv, (void*) &arp_pkt, sizeof(struct arp_packet), 0, NULL, NULL)) < 0)
			{
				perror("Recv error");
				exit(1);
			}
			if(htons(arp_pkt.eth_hdr.ether_type) == 0x0806)			//ARP packet
			{
				if(flag == 1)	//flag == 1
				{
					printf("Get ARP packet - Who has %s?     ", get_target_protocol_addr(&(arp_pkt.arp)));
					printf("Tell %s \n", get_sender_protocol_addr(&(arp_pkt.arp)));
				}
				else        //flag == 2
				{
					if(strcmp(argv[2], get_target_protocol_addr(&(arp_pkt.arp))) == 0)		//compare arg ip and target ip 
					{
						printf("Get ARP packet - Who has %s?     ", argv[2]);
						printf("Tell %s \n", get_sender_protocol_addr(&(arp_pkt.arp)));
					}
				}
			}
		 }
	 }
	
	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(1);
	}
	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */

if(flag == 3 || flag == 4)		
	 {
		ioctl(sockfd_send, SIOCGIFFLAGS,  &req);
		req.ifr_flags |= IFF_PROMISC;
		ioctl(sockfd_send, SIOCSIFFLAGS, &req);
	
		struct sockaddr_in *sin_ptr;		//get host ip address
		strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
		if(ioctl(sockfd_send, SIOCGIFADDR, &req) < 0) 
		{
			perror("SIOCGIFADDR");
			exit(1);
		}
		sin_ptr = (struct sockaddr_in *)&req.ifr_addr;
		myip = sin_ptr->sin_addr;
     
		if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1) 
		{
			perror("SIOCGIFHWADDR");
			exit(1);
		}
	
		int i = 0;		//get host mac address
		while(i<6)
		{
			mac_addr[i] = req.ifr_hwaddr.sa_data[i];
			i++;
		}
	
		if (ioctl(sockfd_send, SIOCGIFINDEX, &req) < 0) 	//接口type
		{
			perror("SIOCGIFINDEX");
			exit(1);
		}
		ifindex = req.ifr_ifindex;
	
		// Fill the parameters of the sa.
		memset(&sa, 0, sizeof(sa));
		sa.sll_family = AF_PACKET;
		sa.sll_protocol = htons(ETH_P_ARP);
		sa.sll_ifindex = ifindex;
		sa.sll_hatype = ARPHRD_ETHER;
		sa.sll_pkttype = PACKET_BROADCAST;
		sa.sll_halen = ETHER_ADDR_LEN;
		memcpy(sa.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);
	}
	
	if(flag == 3)	//set the ARP packet format - request
	{
		memcpy(arp_pkt.eth_hdr.ether_dhost, ether_broadcast_addr, ETHER_ADDR_LEN);	//ethernet header -> ethernet destination addr
		memcpy(arp_pkt.eth_hdr.ether_shost, mac_addr, ETHER_ADDR_LEN);		//ethernet header -> ethernet source addr
		arp_pkt.eth_hdr.ether_type = htons(ETHERTYPE_ARP);		//ethernet header -> frame type
		set_hard_type(&(arp_pkt.arp), ARPHRD_ETHER);				//ethernet type
		set_prot_type(&(arp_pkt.arp), ETHERTYPE_IP);							//protocal type//ETH_P_IP
		set_hard_size(&(arp_pkt.arp), 6);										//ethernet size
		set_prot_size(&(arp_pkt.arp), 4);										//protocol size
		set_op_code(&(arp_pkt.arp), 1);										//op code
		set_sender_hardware_addr(&(arp_pkt.arp), mac_addr);				//sender ethernet address
		set_sender_protocol_addr(&(arp_pkt.arp), inet_ntoa(myip));			//sender protocol address
		unsigned char target_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		set_target_hardware_addr(&(arp_pkt.arp), target_mac);				//target ethernet address
		set_target_protocol_addr(&(arp_pkt.arp), argv[2]);						//target protocol address
		
		if((send_size = sendto(sockfd_send, (void *)&arp_pkt, sizeof(arp_pkt ), 0, (struct sockaddr *)&sa, sizeof(sa)))<0)
		{
			perror("sendto");
			exit(1);
		}
		while(1)
		{
			if((recv_size = recvfrom(sockfd_recv, (void*) &recv_packet, sizeof(struct arp_packet), 0, NULL, NULL)) < 0)
			{
				perror("Recv error");
				exit(1);
			}
			if(htons(recv_packet.eth_hdr.ether_type) == 0x0806 && recv_packet.arp.arp_op == htons(2) && strcmp(argv[2], get_sender_protocol_addr(&(recv_packet.arp))) == 0)	//receive a reply
			{
				printf("The mac address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n", argv[2],
							recv_packet.arp.arp_sha[0], recv_packet.arp.arp_sha[1], recv_packet.arp.arp_sha[2],
							recv_packet.arp.arp_sha[3], recv_packet.arp.arp_sha[4], recv_packet.arp.arp_sha[5]);
				exit(1);
			}
		}
	}



	
	
	close(sockfd_recv);
	close(sockfd_send);
	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	return 0;
}

