#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>


NTSTATUS sdk::readEntry(ULONG64 Base, ULONG64 Index, ULONG64* Entry, const char* entryName)
{
	
	NTSTATUS status;
	PHYSICAL_ADDRESS physaddy;
	physaddy.QuadPart = Base + (Index * 8);
	
	status = sdk::ReadPhysMem(Entry, physaddy, sizeof(ULONG64));
	if(!NT_SUCCESS(status))
	{
		Log::print("Failed to read physical memory for %s", entryName);
		return status;
	}
	if (*Entry == 0 || !(*Entry & 0x1))  // 
	{
		//Log::print("%s entry invalid: 0x%llx", entryName, *Entry);	
		return STATUS_UNSUCCESSFUL;
	}
	//Log::print("%s Entry: 0x%llx", entryName, *Entry);
	
	return STATUS_SUCCESS;
}