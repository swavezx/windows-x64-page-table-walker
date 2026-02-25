#pragma once


#define PAGE_MASK 0x000FFFFFFFFFF000;
#define PML4_INDEX(va) (((va) >> 39) & 0x1FF)
#define PDTD_INDEX(va) (((va) >> 30) & 0x1FF)
#define PD_INDEX(va) (((va) >> 21) & 0x1FF)
#define PT_INDEX(va) (((va) >> 12) & 0x1FF)

#define PT_Walk CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GetData CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1817, METHOD_BUFFERED, FILE_ANY_ACCESS)