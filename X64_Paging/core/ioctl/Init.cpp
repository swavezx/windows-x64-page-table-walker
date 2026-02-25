#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>
#include <defines.h>





NTSTATUS sdk::ioctl::Init(PDRIVER_OBJECT drvobj, PUNICODE_STRING path)
{
	UNREFERENCED_PARAMETER(path);
	Log::print("IOCTL Init called\n");


	PDEVICE_OBJECT device_obj = NULL;

	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\PageTableWalker");
	UNICODE_STRING symb = RTL_CONSTANT_STRING(L"\\DosDevices\\PageTableWalker");

	NTSTATUS status = IoCreateDevice(
		drvobj,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&device_obj
	);

	if (!NT_SUCCESS(status))
	{
		Log::print("Failed to create device object\n");
		Log::print("Status: 0x%X\n", status);
		return status;
	}

	drvobj->MajorFunction[IRP_MJ_CREATE] = &sdk::ioctl::Handler;
	drvobj->MajorFunction[IRP_MJ_CLOSE] = &sdk::ioctl::Handler;
	drvobj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &sdk::ioctl::DeviceControl;
	
	status = IoCreateSymbolicLink(&symb, &deviceName);
	if (!NT_SUCCESS(status))
	{
		Log::print("Failed to create symbolic link\n");
		return status;
	}


	device_obj->Flags |= DO_BUFFERED_IO;
	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	


	return STATUS_SUCCESS;
}