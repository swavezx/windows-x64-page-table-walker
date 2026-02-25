#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>
#include <defines.h>
#include "structs.h"

/*/ CURRENTLY NOT WORKING*/

NTSTATUS sdk::ErasePEHeader(PVOID ModuleBase) {
    if (!ModuleBase) {
        return STATUS_INVALID_PARAMETER;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

    // Validierung
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        Log::Prodprint("[-] Invalid DOS signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ModuleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Log::Prodprint("[-] Invalid NT signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    DWORD headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;

    Log::Prodprint("[+] Erasing PE header: Base=0x%p, Size=0x%X\n", ModuleBase, headerSize);

  
    RtlZeroMemory(ModuleBase, headerSize);


    Log::Prodprint("[+] PE header erased successfully\n");

    return STATUS_SUCCESS;
}