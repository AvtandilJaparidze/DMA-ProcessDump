#pragma once

#include <cstdint>

struct _IMAGE_DOS_HEADER
{
	unsigned short e_magic;	   // 0x0
	unsigned short e_cblp;	   // 0x2
	unsigned short e_cp;	   // 0x4
	unsigned short e_crlc;	   // 0x6
	unsigned short e_cparhdr;  // 0x8
	unsigned short e_minalloc; // 0xa
	unsigned short e_maxalloc; // 0xc
	unsigned short e_ss;	   // 0xe
	unsigned short e_sp;	   // 0x10
	unsigned short e_csum;	   // 0x12
	unsigned short e_ip;	   // 0x14
	unsigned short e_cs;	   // 0x16
	unsigned short e_lfarlc;   // 0x18
	unsigned short e_ovno;	   // 0x1a
	unsigned short e_res[4];   // 0x1c
	unsigned short e_oemid;	   // 0x24
	unsigned short e_oeminfo;  // 0x26
	unsigned short e_res2[10]; // 0x28
	int32_t e_lfanew;		   // 0x3c
};

struct _IMAGE_FILE_HEADER
{
	unsigned short Machine;				 // 0x0
	unsigned short NumberOfSections;	 // 0x2
	unsigned int TimeDateStamp;			 // 0x4
	unsigned int PointerToSymbolTable;	 // 0x8
	unsigned int NumberOfSymbols;		 // 0xc
	unsigned short SizeOfOptionalHeader; // 0x10
	unsigned short Characteristics;		 // 0x12
};

// 0xe0 bytes (sizeof)
struct _IMAGE_OPTIONAL_HEADER
{
	unsigned short Magic;							// 0x0
	unsigned char MajorLinkerVersion;				// 0x2
	unsigned char MinorLinkerVersion;				// 0x3
	unsigned int SizeOfCode;						// 0x4
	unsigned int SizeOfInitializedData;				// 0x8
	unsigned int SizeOfUninitializedData;			// 0xc
	unsigned int AddressOfEntryPoint;				// 0x10
	unsigned int BaseOfCode;						// 0x14
	int64_t ImageBase;								// 0x1c
	unsigned int SectionAlignment;					// 0x20
	unsigned int FileAlignment;						// 0x24
	unsigned short MajorOperatingSystemVersion;		// 0x28
	unsigned short MinorOperatingSystemVersion;		// 0x2a
	unsigned short MajorImageVersion;				// 0x2c
	unsigned short MinorImageVersion;				// 0x2e
	unsigned short MajorSubsystemVersion;			// 0x30
	unsigned short MinorSubsystemVersion;			// 0x32
	unsigned int Win32VersionValue;					// 0x34
	unsigned int SizeOfImage;						// 0x38
	unsigned int SizeOfHeaders;						// 0x3c
	unsigned int CheckSum;							// 0x40
	unsigned short Subsystem;						// 0x44
	unsigned short DllCharacteristics;				// 0x46
	int64_t SizeOfStackReserve;						// 0x48
	int64_t SizeOfStackCommit;						// 0x4c
	int64_t SizeOfHeapReserve;						// 0x50
	int64_t SizeOfHeapCommit;						// 0x54
	unsigned int LoaderFlags;						// 0x58
	unsigned int NumberOfRvaAndSizes;				// 0x5c
	struct _IMAGE_DATA_DIRECTORY DataDirectory[16]; // 0x60
};

struct _IMAGE_NT_HEADERS
{
	unsigned int Signature;						  // 0x0
	struct _IMAGE_FILE_HEADER FileHeader;		  // 0x4
	struct _IMAGE_OPTIONAL_HEADER OptionalHeader; // 0x18
};