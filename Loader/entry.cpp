#include <iostream>
#include <windows.h>
#define PT_Walk CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GetData CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1817, METHOD_BUFFERED, FILE_ANY_ACCESS)

HANDLE driver_Handle;

typedef struct _KERNEL_DATA {
	PVOID Ubase_adress;
	ULONG64 Uphisaddy;
	WCHAR message[256];
}KERNEL_DATA, * PKERNEL_DATA;




KERNEL_DATA data = { 0 };
DWORD bytesReturned;
bool result;




int main()
{
	
	
	driver_Handle = CreateFileW(L"\\\\.\\\PageTableWalker", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(driver_Handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to open driver handle. Error: " << GetLastError() << std::endl;
		system("pause");
		return 1;
	}

	std::cout << "Data: " << data.Ubase_adress << std::endl;

	result =
		DeviceIoControl(
			driver_Handle,
			GetData,
			NULL,
			0,
			&data,
			sizeof(KERNEL_DATA),
			&bytesReturned,
			NULL
		);
	std::cout << "DeviceIoControl result: " << result << ", bytes returned: " << bytesReturned << std::endl;
	std::cout << "Used Ioctl code: 0x" << std::hex << std::uppercase << GetData << std::endl;

	if (result)
	{
		std::cout << "Data received from driver:" << std::endl;
		std::cout << "base adress -> " << data.Ubase_adress << std::endl;
	}

	system("pause");

	return 0;
}