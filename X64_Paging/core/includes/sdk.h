#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <wdm.h>



extern PEPROCESS g_TargetProcess;
extern ULONG64 g_TargetCr3;
extern PVOID base;

// System Information Class
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;

// Process Information Structure
typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);




struct PT_Entries
{
    ULONG64 PML4_entry;
    ULONG64 PDPT_entry;
    ULONG64 PD_entry;
    ULONG64 PT_entry;
};

typedef struct _KERNEL_DATA {
    PVOID Ubase_adress;
    ULONG64 Uphisaddy;
    WCHAR message[256];
};

extern _KERNEL_DATA g_KernelData;
extern _KERNEL_DATA* Kdata;

namespace sdk {
    NTSTATUS InitializeUndocumentedFunctions();
    NTSTATUS FindProcess(const wchar_t* processname);
	NTSTATUS ReadVirtualMem(PVOID buffer, PVOID virtualAddy, SIZE_T size);
	NTSTATUS ReadPhysMem(PVOID buffer, PHYSICAL_ADDRESS physAddr, SIZE_T size);
    NTSTATUS readEntry(ULONG64 Base, ULONG64 Index, ULONG64* Entry, const char* entryName);
    NTSTATUS ErasePEHeader(PVOID ModuleBase);

	namespace ioctl
    {
        NTSTATUS Init(PDRIVER_OBJECT drvobj, PUNICODE_STRING path);
        NTSTATUS Handler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
        NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	}
}



namespace Log
{
    void print(const char* text, ...);
    void Prodprint(const char* text, ...);
}


namespace func
{
    NTSTATUS PT_walk(ULONG64 virtualaddy);
}

