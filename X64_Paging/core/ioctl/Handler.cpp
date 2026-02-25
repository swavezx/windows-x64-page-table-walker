#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>
#include <defines.h>




NTSTATUS sdk::ioctl::Handler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	Log::print("IOCTL Handler called\n");

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	switch (stack->MajorFunction)
	{


		case IRP_MJ_CREATE:
			Log::print("IRP_MJ_CREATE called\n");
			break;
		case IRP_MJ_CLOSE:
			Log::print("IRP_MJ_CLOSE called\n");
			break;
		

	default:
		break;
	}


	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS sdk::ioctl::DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	


	Log::print("Device Control called\n");

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG bytesReturned = 0;

	NTSTATUS status = STATUS_SUCCESS;
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	switch (controlCode)
	{
		case PT_Walk:
			Log::print("PT_Walk received\n"); 
			
			break;
		case GetData:
		{
			Log::Prodprint("GetData received\n");

			if (inputBufferLength < sizeof(_KERNEL_DATA)) {
				Log::print("ERROR: Input buffer too small! Need %lu, got %lu\n",
					sizeof(_KERNEL_DATA), inputBufferLength);
				status = STATUS_BUFFER_TOO_SMALL;
				Log::print("status: 0x%X\n", status);
				Irp->IoStatus.Information = bytesReturned;
				return status;
			}

			if (outputBufferLength < sizeof(_KERNEL_DATA)) {
				Log::print("ERROR: Output buffer too small! Need %lu, got %lu\n",
					sizeof(_KERNEL_DATA), outputBufferLength);
				status = STATUS_BUFFER_TOO_SMALL;
				Log::print("status: 0x%X\n", status);
				Irp->IoStatus.Information = bytesReturned;
				return status;
			}

			if (inputBuffer == NULL) {
				Log::print("ERROR: SystemBuffer is NULL!\n");
				status = STATUS_INVALID_PARAMETER;
				Log::print("status: 0x%X\n", status);
				Irp->IoStatus.Information = bytesReturned;
				return status;
			}

			Log::print("Buffers validated. Casting...\n");
			Log::Prodprint("Buffers validated. Casting...\n");
			

			_KERNEL_DATA* kernelData = (_KERNEL_DATA*)outputBuffer;
			Log::print("Output buffer adress: 0x%llx\n", kernelData);

			Kdata->Ubase_adress = base;

			Log::print("base adress: 0x%llx\n", Kdata->Ubase_adress);

			bytesReturned = sizeof(_KERNEL_DATA);
			Log::print("Data sent to usermode\n");

			break;
		}

		default:
			Log::print("Unknown IOCTL code: 0x%X\n", controlCode);
			break;
	}
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = bytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}