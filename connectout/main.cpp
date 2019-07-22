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
#include "IsIPInRange.h"
#include "myGetAdaptersInfo.h"
using namespace std;
#pragma comment(lib,"wpcap")
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

vector<iprange_str> g_vec_iprange_str;

int main()
{
	map<string, string> map_desc_adapt;
	map_desc_adapt = myGetAdaptersInfo();
	
	iprange_str iprange_strobj;

	iprange_strobj.start_ip = "192.168.0.1";
	iprange_strobj.end_ip = "192.168.0.10";
	g_vec_iprange_str.push_back(iprange_strobj);

	iprange_strobj.start_ip = "0.0.0.0";
	iprange_strobj.end_ip = "255.255.255.255";
	g_vec_iprange_str.push_back(iprange_strobj);
	
	

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

	map<int, string> map_num_adaptname;

	//输出所有网卡信息
	for (d = alldevs; d; d = d->next) {
		/*string tmpname = d->name;
		cout << "num:" << ++i <<"\t" << "name:" << d->name <<"length:"<<tmpname.length()<<"\t";
		if (d->description)
			cout << "description:" << d->description << "\t"<<endl;
		else
			cout << "no description available" << endl;	*/
		
		auto iter = map_desc_adapt.find(d->name);
		if (iter != map_desc_adapt.end()) {
			cout << "Num:" << ++i << "\t" << "网卡名称:" << iter->second <<endl;
			map_num_adaptname.insert(pair<int, string>(i, iter->first));
		}
		
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
	auto iter = map_num_adaptname.find(inum);
	//string tmpstr = iter->second;
	//d->name = tmpstr.c_str();

	if ((adhandle = pcap_open(iter->second.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
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
	auto iter2 = map_desc_adapt.find(iter->second);
	if (iter2 != map_desc_adapt.end()) {
		cout <<"listening on " << iter2->second <<endl;
	}
	
	//printf("\nlistening on %s...\n", iter2->first);
	/* At this point, we don't need any more the device list.
	Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	system("pause");
	return 0;
}