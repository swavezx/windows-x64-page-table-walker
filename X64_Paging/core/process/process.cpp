#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>

#include <intrin.h>



/*/Nearly the entire process.cpp file is made by ai atm as i wanted to learn about 
paging and stuff like this i would rewrite this process stuff completly form scratch soon */


typedef PVOID(*PsGetProcessSectionBaseAddress_t)(PEPROCESS Process);


PsGetProcessSectionBaseAddress_t pPsGetProcessSectionBaseAddress = NULL;

PEPROCESS g_TargetProcess = NULL;
ULONG64 g_TargetCr3 = 0;
PVOID base = nullptr;



NTSTATUS sdk::InitializeUndocumentedFunctions()
{
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"PsGetProcessSectionBaseAddress");

    pPsGetProcessSectionBaseAddress = (PsGetProcessSectionBaseAddress_t)
        MmGetSystemRoutineAddress(&functionName);

    if (!pPsGetProcessSectionBaseAddress)
    {
        Log::print("Failed to resolve PsGetProcessSectionBaseAddress\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}





NTSTATUS sdk::FindProcess(const wchar_t* processname)
{
    PEPROCESS process;
    Log::print("Searching for: %ws\n", processname);
	KIRQL currentIrql = KeGetCurrentIrql();
	Log::print("Current IRQL: %d\n", currentIrql);
    if(currentIrql > PASSIVE_LEVEL)
    {
        Log::print("IRQL too high to query process list!\n");
        return STATUS_UNSUCCESSFUL;
	}
    ULONG bufferSize = 0;
    ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);

    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, 'proc');
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (processInfo->NextEntryOffset)
    {
        if (processInfo->ImageName.Buffer)
        {
            //Log::print("Process: %ws\n", processInfo->ImageName.Buffer);
            if (wcsstr(processInfo->ImageName.Buffer, processname))
            {
              
                
                status = PsLookupProcessByProcessId(processInfo->UniqueProcessId, &process);
				
                
             
               
                if (NT_SUCCESS(status))
                {
                    g_TargetProcess = process;

                    KAPC_STATE apcState;
                    KeStackAttachProcess(process, &apcState);
                    g_TargetCr3 = __readcr3();
                    KeUnstackDetachProcess(&apcState);

                   
                    base = pPsGetProcessSectionBaseAddress(process);

                    ObDereferenceObject(process);
                    Log::Prodprint("Found Process: %ws (PID: %d) ", processInfo->ImageName.Buffer, (ULONG64)processInfo->UniqueProcessId );
					Log::Prodprint("Base Address: 0x%p\n", base);
                    Log::Prodprint("Found Process CR3: 0x%llx\n", g_TargetCr3);
                    break;
                }
            }
        }
        processInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)processInfo + processInfo->NextEntryOffset);
    }
   
    ExFreePoolWithTag(buffer, 'proc');
    return STATUS_SUCCESS;
}