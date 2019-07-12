#pragma once
#define WIN32
#include <pcap.h>
#include <Packet32.h>
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
