//在弹出的框中选择rpcap://\Device\NPF_{E09A61AD-3E3C-4929-B99D-F7D84F795B98
#define HAVE_REMOTE
#define WIN32
#include<pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <cstdlib>
#include <time.h>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include "packet_handler.h"
#include "IsIPInRange.h"
#include "myGetAdaptersInfo.h"
#include "mythead.h"
#include "capture_packet.h"
#include <map>
using namespace std;
#pragma comment(lib,"wpcap")
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")


vector<iprange_str> g_vec_iprange_str;

int main()
{
	int a = 3;
	
	//设置IP地址范围
	iprange_str iprange_strobj;

	iprange_strobj.start_ip = "192.168.0.1";
	iprange_strobj.end_ip = "192.168.0.10";
	g_vec_iprange_str.push_back(iprange_strobj);

	iprange_strobj.start_ip = "0.0.0.0";
	iprange_strobj.end_ip = "255.255.255.255";
	g_vec_iprange_str.push_back(iprange_strobj);

	
	//获取网卡名和描述的对应关系
	map<string, string> map_desc_adapt;
	map_desc_adapt = myGetAdaptersInfo();
	
	auto iter = map_desc_adapt.begin();
	string tmpstr = iter->first;
	iter++;
	string tmpstr2= iter->first;


	if (1) {
		//创建一个线程
		HANDLE thread = CreateThread(NULL, 0, capture_packet, &(tmpstr), 0, NULL);
		//关闭线程
		CloseHandle(thread);

		HANDLE thread2 = CreateThread(NULL, 0, capture_packet, &(tmpstr2), 0, NULL);
		//关闭线程
		CloseHandle(thread2);

	}
		
	system("pause");
	return 0;
}