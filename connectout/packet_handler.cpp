#define WIN32
#include "packet_handler.h"
#include <time.h>
#include <iostream>
#include <string>

using std::cout;
using std::endl;
using std::string;
typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) + Internet header length(4 bits) 
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset(13 bits) 
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;
void packet_handler(u_char* param, const struct pcap_pkthdr
	* header, const u_char* pkt_data);

void packet_handler(u_char* param, const struct pcap_pkthdr
	* header, const u_char* pkt_data)
{
	mac_header* mh;
	ip_header* ih;
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];



	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&time, &local_tv_sec);
	printf("%d/%d/%d ", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday);
	printf("%d:%d:%d ", time.tm_hour, time.tm_min, time.tm_sec);
	cout << "\t";

	mh = (mac_header*)pkt_data;

	ih = (ip_header*)(pkt_data + sizeof(mac_header)); //length of ethernet header

	//目的MAC
	string szDestMac;
	char tmpDestMacChar[6];
	for (int i = 0; i < 5; i++) {
		memset(tmpDestMacChar, 0, 6);
		sprintf(tmpDestMacChar, "%02X-", mh->dest_addr[i]);
		szDestMac = szDestMac + tmpDestMacChar;
	}
	memset(tmpDestMacChar, 0, 6);
	sprintf(tmpDestMacChar, "%02X", mh->dest_addr[5]);
	szDestMac = szDestMac + tmpDestMacChar;


	//目的IP
	string szDestIP;
	char tmpDestIPchar[10];
	for (int i = 0; i < 3; i++) {
		memset(tmpDestIPchar, 0, 10);
		sprintf(tmpDestIPchar, "%d.", ih->daddr[i]);
		szDestIP = szDestIP + tmpDestIPchar;
	}
	memset(tmpDestIPchar, 0, 10);
	sprintf(tmpDestIPchar, "%d", ih->daddr[3]);
	szDestIP = szDestIP + tmpDestIPchar;



	//源MAC
	string szSrcMac;
	char tmpSrcMacchar[6];
	for (int i = 0; i < 5; i++) {
		memset(tmpSrcMacchar, 0, 6);
		sprintf(tmpSrcMacchar, "%02X-", mh->src_addr[i]);
		szSrcMac = szSrcMac + tmpSrcMacchar;
	}
	memset(tmpSrcMacchar, 0, 6);
	sprintf(tmpSrcMacchar, "%02X", mh->src_addr[5]);
	szSrcMac = szSrcMac + tmpSrcMacchar;


	//源IP
	string szSrcIP;
	char tmpSrcIPchar[10];
	for (int i = 0; i < 3; i++) {
		memset(tmpSrcIPchar, 0, 10);
		sprintf(tmpSrcIPchar, "%d.", ih->daddr[i]);
		szSrcIP = szSrcIP + tmpSrcIPchar;
	}
	memset(tmpSrcIPchar, 0, 10);
	sprintf(tmpSrcIPchar, "%d", ih->daddr[3]);
	szSrcIP = szSrcIP + tmpSrcIPchar;


	cout << szSrcMac << "  ---------->  " << szDestMac << "\t" << szSrcIP << "  ------------>  " << szDestIP << endl;


	printf("%d\n", header->len);
	printf("\n");
}