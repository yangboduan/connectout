#pragma once
#include <string>
#include <vector>
using std::string;
using std::vector;
typedef struct ip_range_to_net
{
	unsigned int start_ip;
	unsigned int end_ip;
} ip_range_to_net;

typedef struct ip_range {
	string start_ip;
	string end_ip;
} ip_range;
void SplitString(const string& s, vector<string>& v, const string& c);
vector<ip_range_to_net> do_ip_range_to_net(vector<ip_range> vip_range);
bool isIPInRange(string szIP, vector<ip_range> vec_iprange);
