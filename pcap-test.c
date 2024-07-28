#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <endian.h>

// 엔디안 설정
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LIBNET_LIL_ENDIAN 1
#define LIBNET_BIG_ENDIAN 0

#elif __BYTE_ORDER == __BIG_ENDIAN

#define LIBNET_LIL_ENDIAN 0
#define LIBNET_BIG_ENDIAN 1
#else
#error "Unknown byte order"
#endif


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[6];/* destination ethernet address */
	u_int8_t  ether_shost[6];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
	u_int8_t ip_hl : 4,      /* header length */
		ip_v : 4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
	u_int8_t ip_v : 4,       /* version */
		ip_hl : 4;        /* header length */
#endif
	u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
	u_int8_t ip_ttl;          /* time to live */
	u_int8_t ip_p;            /* protocol */
	u_int16_t ip_sum;         /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};


struct libnet_tcp_hdr
{
	u_int16_t th_sport;       /* source port */
	u_int16_t th_dport;       /* destination port */
	u_int32_t th_seq;          /* sequence number */
	u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
	u_int8_t th_x2 : 4,         /* (unused) */
		th_off : 4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
	u_int8_t th_off : 4,        /* data offset */
		th_x2 : 4;         /* (unused) */
#endif
	u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
	u_int16_t th_wuin;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
};


typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_data(const u_int8_t* data, int length) {
    printf("Data (hexadecimal value): ");
    for (int i = 0; i < length; i++) {
		if( i>=20) 
			break;
        printf("0x%02x ", data[i]);
    }
    printf("\n");
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	//  Open live pcap session on NIC( Each computer has a different network interface.) for capturing

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		
		struct pcap_pkthdr* header;
		const u_int8_t* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		}

		struct libnet_ethernet_hdr* eth_header = (struct libnet_ethernet_hdr*)packet;

		// 이더넷 헤더는 고정 크기 14바이트
		struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)(packet + 14);

		// IPv4 헤더의 길이는 가변일 수 있기 때문에 다음과 같이 계산해야함
		int ip_header_length = ip_header->ip_hl * 4;
		// Ip해더의 길이가 4비트로 저장되는데 이 값은 32비트(4바이트) 단위로 헤더 길이를 나타냄 때문에 4를 곱해주면 헤더의 길이가 나옴
		// 이유는 4비트에 32비트 값을 채워넣어야 되기 때문에 이를 위해서 4를 나눈 것임
		// TCP 헤더의 시작 위치를 계산 (이더넷 헤더 + IPv4 헤더)
		struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet + 14 + ip_header_length);

		// TCP 헤더의 길이는 가변일 수 있기 때문에 다음과 같이 계산해야함
		int tcp_header_length = tcp_header->th_off * 4;
		// TCP 헤더 길이가 4비트로 저장되는데 이 값은 32비트(4바이트) 단위로 헤더 길이를 나타냄 때문에 4를 곱해주면 헤더의 길이가 나옴
		// 이유는 4비트에 32비트 값을 채워넣어야 되기 때문에 이를 위해서 4를 나눈 것임

		// 데이터 부분
		const u_int8_t* Data = packet + 14 + ip_header_length + tcp_header_length;

		int Data_length = header->caplen - (Data - packet); //header->caplen은 현재 캡처된 패킷의 길이를 바이트 단위로 저장
		//즉 현재 식의 의미는 전체 패킷 길이에서 packet 시작에서 data까지의 길이를 빼주면 data의 길이이다.

		printf("%u bytes captured\n", header->caplen);
		printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x / ", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
		printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x \n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
		printf("src ip : %s / ",inet_ntoa(ip_header->ip_src));
		printf("dst ip : %s \n",inet_ntoa(ip_header->ip_dst));
		printf("src port : %d / ",ntohs(tcp_header->th_sport));
		printf("dst port : %d \n",ntohs(tcp_header->th_dport));
		print_data(Data, Data_length);
		printf("-----------------------------------------------------------------------------------------\n");
	}

	pcap_close(pcap);
}
