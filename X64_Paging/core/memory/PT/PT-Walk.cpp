#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>
#include <defines.h>

_KERNEL_DATA g_KernelData = { 0 };
_KERNEL_DATA* Kdata = &g_KernelData;

NTSTATUS func::PT_walk(ULONG64 virtualaddy)
{
	PT_Entries pt;
	PT_Entries* PageTable = &pt;

	ULONG64 PML4_base = g_TargetCr3 & PAGE_MASK;
	if (PML4_base == 0)
	{
		Log::print("Invalid CR3");
		return STATUS_UNSUCCESSFUL;
	}
	ULONG64 PML4_index = PML4_INDEX(virtualaddy);

	

	//sdk::readEntry(PML4_base, PML4_index, &PageTable->PML4_entry, "PML4");
	for(int i = 0; i < 512; i++)
	{
		UINT64 tempEntry;
		sdk::readEntry(PML4_base, i, &tempEntry, "PML4");
		if (tempEntry != 0)//only print mapped pages
		{
			
			//Log::print("PML4 Entry %d: 0x%llx", i, (tempEntry));

		}


		

	}
	sdk::readEntry(PML4_base, PML4_index, &PageTable->PML4_entry, "PML4");//for adress translation
	Log::Prodprint("Used PML4 Entry: 0x%llx", PageTable->PML4_entry);
	

	ULONG64 PDPT_base = PageTable->PML4_entry & PAGE_MASK;
	ULONG64 PDPT_index = PDTD_INDEX(virtualaddy);


	sdk::readEntry(PDPT_base, PDPT_index, &PageTable->PDPT_entry, "PDPT");
	if(PageTable->PDPT_entry & 0x80) //check for large page
	{
		Log::print("1GB page detected at PDPT");
		return STATUS_SUCCESS;
	}


	ULONG64 PD_base = PageTable->PDPT_entry & PAGE_MASK;
	ULONG64 PD_index = PD_INDEX(virtualaddy);
	
	sdk::readEntry(PD_base, PD_index, &PageTable->PD_entry, "PD");
	if (PageTable->PD_entry & 0x80) //check for large page
	{
		Log::print("2MB page detected at PD");
		return STATUS_SUCCESS;
	}



	ULONG64 PT_base = PageTable->PD_entry & PAGE_MASK;
	ULONG64 PT_index = PT_INDEX(virtualaddy);
	
	sdk::readEntry(PT_base, PT_index, &PageTable->PT_entry, "PT");




	ULONG64 page_base = PageTable->PT_entry & PAGE_MASK;
	ULONG64 page_offset = virtualaddy & 0xFFF;

	ULONG64 final_physaddy = page_base + page_offset;
	Log::Prodprint("Final Physical Address: 0x%llx", final_physaddy);
	Log::Prodprint("Virtual: 0x%llx -> Physical: 0x%llx", virtualaddy, final_physaddy);
	PHYSICAL_ADDRESS value;
	PHYSICAL_ADDRESS physaddy;

	physaddy.QuadPart = final_physaddy;
	NTSTATUS status = sdk::ReadPhysMem(&value, physaddy, sizeof(ULONG64));


	if (NT_SUCCESS(status))
	{
		Log::print("Value at phys 0x%llx: 0x%llx", final_physaddy, value);
	}
	Log::print("Value at Physical Address 0x%llx : 0x%llx", virtualaddy, value.QuadPart);

	return status;
}