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
#include <thread>         // std::thread  
#include "ThreadPool.h"
#include <windows.h>
using namespace std;
#pragma comment(lib,"wpcap")
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")
ThreadPool pool(4);
int g_firstrun = 1;
vector<iprange_str> g_vec_iprange_str;
map<string, string> g_current_map_name_desc;
map<string, string> g_last_map_name_desc;
int myfun() {
	while (1) {

		g_current_map_name_desc = myGetAdaptersInfo();

		if (g_firstrun == 1) { //如果是程序启动后第一次运行此程序，则将当前获取的网卡信息赋值给g_last_map_name_desc 
			for (auto iter = g_current_map_name_desc.begin(); iter != g_current_map_name_desc.end(); iter++) {
				pool.enqueue(capture_packet, iter->first);
			}
			//g_last_map_name_desc = g_current_map_name_desc;
			g_firstrun = 0;
		}
		else {//如果不是程序启动后第一次运行此程序
			for (auto iter = g_current_map_name_desc.begin(); iter != g_current_map_name_desc.end(); iter++) {
				auto iter2 = g_last_map_name_desc.find(iter->first);
				if (iter2 == g_last_map_name_desc.end()) {
					cout << "新增了网卡=========================================" << endl;
					pool.enqueue(capture_packet, iter->first);
				}
				
			}

		}
		g_last_map_name_desc = g_current_map_name_desc;
		Sleep(1 * 1000);
	}
}
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


	////获取网卡名和描述的对应关系
	//map<string, string> map_name_desc;
	//map_name_desc = myGetAdaptersInfo();
	//
	//auto iter = map_name_desc.begin();
	//string tmpstr = iter->first;
	//cout << "desc:" << iter->second << endl;
	//iter++;
	//string tmpstr2= iter->first;
	//cout << "desc2:" << iter->second << endl;



	// enqueue and store future
	pool.enqueue(myfun);
	/*pool.enqueue(capture_packet, tmpstr);
	pool.enqueue(capture_packet, tmpstr2);*/







	system("pause");
	return 0;
}