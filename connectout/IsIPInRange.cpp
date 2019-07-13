#include "IsIPInRange.h"
//SplitString ref Url:https://www.cnblogs.com/yuehouse/p/10230589.html
void SplitString(const string& s, vector<string>& v, const string& c)
{
	string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));

		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}
	if (pos1 != s.length())
		v.push_back(s.substr(pos1));
}




vector<ip_range_to_net> do_ip_range_to_net(vector<ip_range> vip_range) {
	vector<ip_range_to_net> vip_range_to_net;
	for (auto it = vip_range.begin();it != vip_range.end(); it++) {
		vector<string> v1;
		SplitString(it->start_ip, v1, "."); //可按多个字符来分隔;
		string tmpstr = v1[0] + v1[1] + v1[2] + v1[3];
		unsigned int uip_start = stoi(v1[0], 0, 10) * 256 * 256 * 256 + stoi(v1[1], 0, 10) * 256 * 256
			+ stoi(v1[2], 0, 10) * 256 + stoi(v1[3], 0, 10);
		vector<string> v2;
		SplitString(it->end_ip, v2, ".");
		string tmpstr2 = v2[0] + v2[1] + v2[2] + v2[3];

		unsigned int uip_end = stoi(v2[0], 0, 10) * 256 * 256 * 256 + stoi(v2[1], 0, 10) * 256 * 256
			+ stoi(v2[2], 0, 10) * 256 + stoi(v2[3], 0, 10);

		ip_range_to_net ip_range_to_netobj;
		ip_range_to_netobj.start_ip = uip_start;
		ip_range_to_netobj.end_ip = uip_end;
		vip_range_to_net.push_back(ip_range_to_netobj);
		

	}

	return vip_range_to_net;
}



bool isIPInRange(string szIP, vector<ip_range> vec_iprange) {
	vector<string> v;
	SplitString(szIP, v, "."); 
	string tmpstr = v[0] + v[1] + v[2] + v[3];
	unsigned int uip= stoi(v[0], 0, 10) * 256 * 256 * 256 + stoi(v[1], 0, 10) * 256 * 256
		+ stoi(v[2], 0, 10) * 256 + stoi(v[3], 0, 10);

	vector<ip_range_to_net>  ip_range_to_netobj;
	ip_range_to_netobj = do_ip_range_to_net(vec_iprange);
	for (auto it = ip_range_to_netobj.begin();it != ip_range_to_netobj.end();it++) {
		if (uip >= it->start_ip and uip <= it->end_ip) {
			return 1;
		}
		
	}

	return 0;
}