//ref URL:https://www.cnblogs.com/Leo-Forest/archive/2013/05/03/3056271.html
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
#include <string.h>

#include "myGetAdaptersInfo.h"
using namespace std;
#pragma comment(lib,"Iphlpapi.lib") //��Ҫ���Iphlpapi.lib��

map<string, string>  myGetAdaptersInfo() {
	{
		map<string , string> map_adapt_desc;
		
		//PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
		PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
		//�õ��ṹ���С,����GetAdaptersInfo����
		unsigned long stSize = sizeof(IP_ADAPTER_INFO);
		//����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
		int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
		//��¼��������
		int netCardNum = 0;
		//��¼ÿ�������ϵ�IP��ַ����
		int IPnumPerNetCard = 0;
		if (ERROR_BUFFER_OVERFLOW == nRel)
		{
			//����������ص���ERROR_BUFFER_OVERFLOW
			//��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
			//��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
			//�ͷ�ԭ�����ڴ�ռ�
			delete pIpAdapterInfo;
			//���������ڴ�ռ������洢����������Ϣ
			pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
			//�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
			nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
		}
		if (ERROR_SUCCESS == nRel)
		{
			//���������Ϣ
			 //�����ж�����,���ͨ��ѭ��ȥ�ж�
			while (pIpAdapterInfo)
			{

				string szTmp ="rpcap://\\Device\\NPF_"; //��ת�壬ԭΪ:rpcap://\Device\NPF_
				//���ϡ�rpcap://\Device\NPF_��Ϊ��Ӧpcap_findalldevs_ex������ȡ����Ϣ
				string szAdapterName = szTmp + (pIpAdapterInfo->AdapterName);//{7C8EE3A4-967A-4AB6-99C5-6FA082B4A74A}
				string szDescription = pIpAdapterInfo->Description;//Realtek USB GbE Family Controller
				
				
				switch (pIpAdapterInfo->Type)
				{
				case MIB_IF_TYPE_OTHER:
					//cout << "�������ͣ�" << "OTHER" << endl;
					break;
				case MIB_IF_TYPE_ETHERNET:
					//cout << "�������ͣ�" << "ETHERNET" << endl;
					break;
				case MIB_IF_TYPE_TOKENRING:
					//cout << "�������ͣ�" << "TOKENRING" << endl;
					break;
				case MIB_IF_TYPE_FDDI:
					//cout << "�������ͣ�" << "FDDI" << endl;
					break;
				case MIB_IF_TYPE_PPP:
					//printf("PP\n");
					//cout << "�������ͣ�" << "PPP" << endl;
					break;
				case MIB_IF_TYPE_LOOPBACK:
					//cout << "�������ͣ�" << "LOOPBACK" << endl;
					break;
				case MIB_IF_TYPE_SLIP:
					//cout << "�������ͣ�" << "SLIP" << endl;
					break;
				default:
				
					break;
				}
				//���˵������к�"Wi-Fi Direct"������
				if (!strstr(szDescription.c_str(),"Wi-Fi Direct")) {
					cout << "����������" << ++netCardNum << endl;
					cout << "�������ƣ�" << szAdapterName << endl;
					cout << "����������" << szDescription << endl;
					cout << "--------------------------------------------------------------------" << endl;

					map_adapt_desc.insert(pair<string, string>(szAdapterName,szDescription ));
				}
				
				
				pIpAdapterInfo = pIpAdapterInfo->Next;
				
			}

		}
		//�ͷ��ڴ�ռ�
		if (pIpAdapterInfo)
		{
			delete pIpAdapterInfo;
		}

		return map_adapt_desc;
	}
}