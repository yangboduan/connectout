#include "mythead.h"

DWORD WINAPI Fun(LPVOID lpParamter)
{
	int *a = (int*)lpParamter;
	//cout << &lpParamter << endl;
	return 0L;
}