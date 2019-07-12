//在弹出的框中选择rpcap://\Device\NPF_{E09A61AD-3E3C-4929-B99D-F7D84F795B98
#define HAVE_REMOTE
#define WIN32
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <cstdlib>
#include <time.h>
#include <iostream>
#include <string>
#include <vector>
#include "packet_handler.h"
using namespace std;
#pragma comment(lib,"wpcap")
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")







int main()
{
	pcap_if_t* alldevs;//指向pcap_if_t结构的指针
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	u_int netmask;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];

	char szSource[] = PCAP_SRC_IF_STRING;// #define PCAP_SRC_IF_STRING "rpcap://" 表示本地适配器
	// 从本地获取网络接口设备列表,存储在alldevs中
	if (pcap_findalldevs_ex(szSource, NULL, &alldevs,errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n",errbuf);
		exit(1);
	}


	//输出所有网卡信息
	for (d = alldevs; d; d = d->next) {
		cout << "Num:" << ++i <<"\t" << "name:" << d->name <<"\t";
		if (d->description)
			cout << "description:" << d->description << "\t"<<endl;
		else
			cout << "No description available" << endl;		
	}


	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* Open the adapter */

	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr,"%s", "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	//用pcap_datalink()检查MAC层，以确保我们处理的是以太网, DLT_EN10MB 代表以太网（10Mb, 100Mb, 1000Mb, 或者更高）
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;
	//compile the filter
	if (pcap_compile(adhandle, &fcode, "ip", 1, netmask) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);
	/* At this point, we don't need any more the device list.
	Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	system("pause");
	return 0;
}
