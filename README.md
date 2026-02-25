# Windows x64 Kernel Page Table Walker

A Windows kernel driver that manually walks the x64 page table hierarchy to translate virtual addresses to physical addresses for arbitrary processes.

> ⚠️ **Educational/Research purposes only.** Requires a kernel driver loaded on the target system.

---

## What It Does

Given a target process and a virtual address, this driver:

1. Finds the target process by name using `ZwQuerySystemInformation`
2. Reads the process CR3 register (PML4 base) by attaching to the process via `KeStackAttachProcess`
3. Manually walks the 4-level page table hierarchy using physical memory reads
4. Translates the virtual address to its physical address
5. Reads the value at the resulting physical address via `MmCopyMemory`

---

## How x64 Paging Works

x64 uses a 4-level page table structure. A 64-bit virtual address is split into indices for each level:

```
Virtual Address (64-bit):
[ PML4 Index (9) | PDPT Index (9) | PD Index (9) | PT Index (9) | Page Offset (12) ]
```

Each level contains entries pointing to the next level's physical base address. The driver reads each entry using direct physical memory access.

| Level | Name | Index Bits | Points To |
|---|---|---|---|
| 1 | PML4 | [47:39] | PDPT base |
| 2 | PDPT | [38:30] | PD base (or 1GB page) |
| 3 | PD | [29:21] | PT base (or 2MB page) |
| 4 | PT | [20:12] | Physical page base |

The physical address is then: `PT_entry & PAGE_MASK + VirtualAddress & 0xFFF`

---

## Implementation Details

### Process Discovery
Uses `ZwQuerySystemInformation` with `SystemProcessInformation` to enumerate all running processes and find the target by name. The CR3 is captured by attaching to the process context with `KeStackAttachProcess` and reading `__readcr3()`.

### Physical Memory Reading
All page table entries are read directly from physical memory using `MmCopyMemory` with `MM_COPY_MEMORY_PHYSICAL`. This avoids any virtual address translation for the reads themselves.

### Large Page Detection
The walker checks for large pages at each level:
- **Bit 7 set at PDPT** → 1GB page, translation stops here
- **Bit 7 set at PD** → 2MB page, translation stops here

### PE Header Erasure
Includes a utility to erase the PE header of a loaded module in memory by zeroing `SizeOfHeaders` bytes at the module base — a common anti-forensics technique used to hide loaded drivers.

### Pattern Scanning
Includes a signature scanner (`FindPattern`) for locating byte patterns in kernel memory — useful for finding undocumented structures or functions by signature rather than hardcoded offsets.



---


## Current Limitations

- IOCTL communication interface is not yet implemented — currently target process and virtual address are hardcoded
- `ErasePEHeader` is marked as not working in the current build
- `process.cpp` is partially AI-assisted and will be rewritten from scratch

---

## What I Learned Building This

- How x64 virtual-to-physical address translation works at the hardware level
- How Windows stores per-process page tables and why CR3 differs per process
- How to read physical memory directly from a kernel driver using `MmCopyMemory`
- How large pages (1GB/2MB) short-circuit the normal 4-level walk
- How `KeStackAttachProcess` temporarily switches the driver into another process's address space
