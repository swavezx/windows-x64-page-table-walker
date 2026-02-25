#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>


NTSTATUS sdk::ReadPhysMem(PVOID buffer, PHYSICAL_ADDRESS physAddr, SIZE_T size)
{

	MM_COPY_ADDRESS addr = { 0 };
	addr.PhysicalAddress = physAddr;

	SIZE_T bytesRead = 0;

	NTSTATUS status = MmCopyMemory(
		buffer,
		addr,
		size,
		MM_COPY_MEMORY_PHYSICAL,
		&bytesRead
	);

	if (!NT_SUCCESS(status) || bytesRead != size)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

NTSTATUS sdk::ReadVirtualMem(PVOID buffer, PVOID virtualAddy, SIZE_T size)
{

	MM_COPY_ADDRESS addr = { 0 };
	addr.VirtualAddress = virtualAddy;


	SIZE_T bytesRead = 0;

	NTSTATUS status = MmCopyMemory(
		buffer,
		addr,
		size,
		MM_COPY_MEMORY_VIRTUAL,
		&bytesRead
	);

	if (!NT_SUCCESS(status) || bytesRead != size)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}