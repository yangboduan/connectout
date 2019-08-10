#include <iostream>
#include <sstream>
#include "getconfigcontent.h"
using std::ostringstream;
using std::string;

#define MAX_LENGTH 500
string getconfigcontent() {
	char SName[MAX_LENGTH];
	
	GetPrivateProfileString((LPCTSTR)"Student", (LPCTSTR)"Name", (LPCTSTR)"DefaultName", (LPTSTR) SName, MAX_LENGTH, (LPCTSTR)"C:\\config.ini");
	//std::cout << SName << std::endl;
	string strvalue;
	ostringstream ossvalue;
	ossvalue<<SName;
	return ossvalue.str();
	
}