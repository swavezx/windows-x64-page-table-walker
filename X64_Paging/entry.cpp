#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>
#include <defines.h>





extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	Log::print("Driver Loaded");
	sdk::InitializeUndocumentedFunctions();

	NTSTATUS status = sdk::FindProcess(L"notepad.exe");
	if (!NT_SUCCESS(status))
	{
		Log::print("Could not find target process!");
		return status;
	}

	ULONG64 cr4 = __readcr4(); //if 1 PAE is enabled, if 0 then no PAE
	Log::Prodprint("CR4: 0x%llx", cr4);

	PVOID driverBase = DriverObject->DriverStart;
	status = sdk::ErasePEHeader(driverBase);
	Log::Prodprint("Driver base address: 0x%p", driverBase);
	Log::Prodprint("Erasing PE header");
	if (!NT_SUCCESS(status))
	{
		Log::Prodprint("Failed to erase PE header! Status: 0x%X", status);
	}

		func::PT_walk(0xB4EC59BB38);
	
	return IoCreateDriver(NULL, &sdk::ioctl::Init);
}