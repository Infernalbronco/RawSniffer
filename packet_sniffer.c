#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#define ETH_HDR_LEN 14
#define ETH_ADDR_LEN 6

struct eth_header{

	unsigned char eth_src_addr[ETH_ADDR_LEN];
	unsigned char eth_dest_addr[ETH_ADDR_LEN];
	unsigned short eth_type;
};

struct ip_header{

	unsigned char ip_ver_and_ihl;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_flag;
	unsigned short ip_frag_offset;
	unsigned char ip_ttl;
	unsigned short ip_prot_type;
	unsigned short ip_checksum;
	unsigned int  ip_src_addr;
	unsigned int ip_dest_addr;
};

struct tcp_header{

	unsigned short tcp_src_port;
	unsigned short tcp_dest_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char reserved:4;
	unsigned char tcp_offset:4;
	unsigned char tcp_flag;

	#define TCP_FIN 0x01
	#define TCP_SYN 0x02
	#define TCP_RST 0x04
	#define TCP_PUSH 0x08
	#define TCP_ACK 0x10
	#define TCP_URG 0x20

	unsigned char tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent;
};

void dump(unsigned char *buffer , const unsigned int len){

	unsigned char byte;
	unsigned int i , j;

	for (i = 0  ; i < len ; i++)
	{
		printf ("%02x " , buffer[i]);
		if ((i%16)==15 || i == len-1){
			for (j = 0 ; j <= 15-(i%16) ; j++)
				printf (" ");
			printf ("|");

			for (j = (i-(i%16)) ; j <= i ; j++){

				byte = buffer[j];
				if ((byte>31) && (byte < 127))
					printf ("%c",byte);
				else
					printf ("."); 
			} 
			printf ("\n");
 		}
	}
}

void pcap_fatal(unsigned char *failed_in , const char *errbuf){

	printf ("Fatal error in %s:%s\n" , failed_in , errbuf);
	exit(1);
}


void decode_eth(const unsigned char *header_start){

	const struct eth_header  *eth_header;
	eth_header = (const struct eth_header*)header_start;
	printf ("[[  Layer 2 :: Ethernet Header  ]]\n");
	printf ("[ Source : %02x" , eth_header->eth_src_addr[0]);
	int i ;

	for (i = 1 ; i < ETH_ADDR_LEN ; i++)
		printf (":%02x" , eth_header->eth_src_addr[i]);

	printf ("\tDestination : %02x" , eth_header->eth_dest_addr[0]);
	for (i = 1 ; i < ETH_ADDR_LEN ; i++)
		printf (":%02x" , eth_header->eth_dest_addr[i]);

	printf ("\tType:%hu ]\n", ntohs(eth_header->eth_type));
}

void decode_ip(const unsigned char *header_start){

	const struct ip_header *ip_header;
	struct in_addr src_addr , dest_addr;

	ip_header = (const struct ip_header*)header_start;

	src_addr.s_addr = ip_header->ip_src_addr;
	dest_addr.s_addr = ip_header->ip_dest_addr;

	printf ("\t[[ Layer 3 ::: IP Header ]]\n");
	printf ("\t [ Source : %s" , inet_ntoa(src_addr));
	printf ("\tDestination : %s ]\n", inet_ntoa(dest_addr));
	printf ("\t [ Type : %hu\tID:%hu\tLength:%hu ]\n" ,ntohs(ip_header->ip_prot_type) , ntohs(ip_header->ip_id) , ntohs(ip_header->ip_len)); 
}

unsigned int decode_tcp(const unsigned char *header_start){

	unsigned int tcp_header_size;
	const struct tcp_header *tcp_header;
	tcp_header = (const struct tcp_header *)header_start;
	tcp_header_size = 4*(tcp_header->tcp_offset);

	printf ("\t\t [[ Layer 4 :::: TCP Header ]]\n");
	printf ("\t\t [ Source Port : %hu\tDestination Port : %hu ]\n" , ntohs(tcp_header->tcp_src_port) , ntohs(tcp_header->tcp_dest_port) );
	printf ("\t\t [ Seq #:%u\tAck:%u ]\n",ntohl(tcp_header->tcp_seq) , ntohl(tcp_header->tcp_ack));
	printf ("\t\t [ Header size:%u\tFlags: ",tcp_header_size);
	if (tcp_header->tcp_flag & TCP_FIN)
		printf ("FIN ");
	if (tcp_header->tcp_flag & TCP_SYN)
		printf ("SYN ");
	if (tcp_header->tcp_flag & TCP_RST)
		printf ("RST ");
	if (tcp_header->tcp_flag & TCP_PUSH)
		printf ("PUSH ");
	if (tcp_header->tcp_flag & TCP_ACK)
		printf ("ACK ");
	if (tcp_header->tcp_flag & TCP_URG)
		printf ("URG ");

	printf ("]\n"); 
}

void caught_packet(unsigned char *args , const struct pcap_pkthdr *cap_header , const unsigned char *packet){

	unsigned int tcp_header_size , data_len , total_header_size;
	unsigned char *pkt_data;

	printf ("===Got %d Bytes===\n" , cap_header->len);

	decode_eth(packet);
	decode_ip(packet+ETH_HDR_LEN);

	tcp_header_size = decode_tcp(packet + ETH_HDR_LEN + sizeof(struct ip_header));

	total_header_size = tcp_header_size + ETH_HDR_LEN + sizeof(struct ip_header);

	pkt_data =(unsigned char*)packet + total_header_size;
	data_len = cap_header->len - total_header_size;

	if (data_len > 0){
		dump (pkt_data , data_len);
	}else{
		printf ("\t\t\t No packet data\n");
	}
}

void main(){

	struct pcap_pkthdr cap_header;
	const unsigned char *packet;
	char *device;
	pcap_t *pcap_handle;

	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	device = pcap_lookupdev(errbuf);
	if (device == NULL)
		pcap_fatal("pcap_lookupdev" , errbuf);

	printf ("Sniffing on device %s\n" , device);

	pcap_handle = pcap_open_live(device , 4096 , 1 , 0 , errbuf);
	if (pcap_handle == NULL)
		pcap_fatal("pcap_open_live" , errbuf);

	pcap_loop (pcap_handle , -1 , caught_packet , NULL);
	
	pcap_close(pcap_handle);
}
