#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>


BOOLEAN bDataCompare(const UCHAR* pData, const UCHAR* bMask, const char* szMask) //maybe change UCHAR to BYTE back
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
	
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	
	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, UCHAR* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((UCHAR*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);
	return 0;
}