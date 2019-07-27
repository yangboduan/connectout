#define HAVE_REMOTE
#define WIN32
#define WIN32_LEAN_AND_MEAN 
#include "capture_packet.h"
#include <pcap.h>
#include <Packet32.h>
#include <map>
#include <string>
#include "myGetAdaptersInfo.h"
#include "packet_handler.h"
using namespace std;
#pragma comment(lib,"wpcap")
//int capture_packet(string szAdaptName)
DWORD capture_packet(LPVOID szAdaptName) {
	//获取网卡名和描述的对应关系
	string * a = (string *)szAdaptName;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* adhandle;
	if ((adhandle = pcap_open(a->c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "%s", "\nUnable to open the adapter. %s is not supported by WinPcap\n");

		return -1;
	}

	//用pcap_datalink()检查MAC层，以确保我们处理的是以太网, DLT_EN10MB 代表以太网（10Mb, 100Mb, 1000Mb, 或者更高）
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");

		return -1;
	}

	//compile the filter

	struct bpf_program fcode;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_lookupnet(a->c_str(), &net, &mask, errbuf);
	if (pcap_compile(adhandle, &fcode, "ip", 1, mask) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");

		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");

		return -1;
	}

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
}