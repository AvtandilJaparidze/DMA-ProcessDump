#include "memory.h"
#include "vector"
#include <fstream>
#include <algorithm>
#include <thread>
#include <sstream>

#include "windows_types.h"

uint64_t cbSize = 0x80000;
//callback for VfsFileListU
VOID cbAddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
	if (strcmp(uszName, "dtb.txt") == 0)
		cbSize = cb;
}

struct Info
{
	uint32_t index;
	uint32_t process_id;
	uint64_t dtb;
	uint64_t kernelAddr;
	std::string name;
};

bool Memory::FixDtb(DWORD processID, const char *name)
{
	PVMMDLL_MAP_MODULEENTRY module_entry = NULL;
	bool result = VMMDLL_Map_GetModuleFromNameU(hVMM, processID, name, &module_entry, NULL);
	if (result)
	{
		return true;
	}

	while (true)
	{
		BYTE bytes[4] = {0};
		DWORD i = 0;

		auto nt = VMMDLL_VfsReadU(hVMM, "\\misc\\procinfo\\progress_percent.txt", bytes, 3, &i, 0);

		if (nt == VMMDLL_STATUS_SUCCESS && atoi(reinterpret_cast<LPSTR>(bytes)) == 100)
		{
			break;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	VMMDLL_VFS_FILELIST2 VfsFileList;
	VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
	VfsFileList.h = 0;
	VfsFileList.pfnAddDirectory = 0;
	VfsFileList.pfnAddFile = cbAddFile;

	result = VMMDLL_VfsListU(hVMM, "\\misc\\procinfo\\", &VfsFileList);
	if (!result)
	{
		return false;
	}

	//read the data from the txt and parse it
	const size_t buffer_size = cbSize;
	std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
	DWORD j = 0;
	auto nt = VMMDLL_VfsReadU(hVMM, "\\misc\\procinfo\\dtb.txt", bytes.get(), buffer_size - 1, &j, 0);
	if (nt != VMMDLL_STATUS_SUCCESS)
	{
		return false;
	}

	std::vector<uint64_t> possible_dtbs = { };
	std::string lines(reinterpret_cast<char*>(bytes.get()));
	std::istringstream iss(lines);
	std::string line = "";

	while (std::getline(iss, line))
	{
		Info info = { };

		std::istringstream info_ss(line);
		if (info_ss >> std::hex >> info.index >> std::dec >> info.process_id >> std::hex >> info.dtb >> info.kernelAddr >> info.name)
		{
			if (info.process_id == 0) //parts that lack a name or have a NULL pid are suspects
			{
				possible_dtbs.push_back(info.dtb);
			}
			if (info.name.find(name) != std::string::npos)
			{
				possible_dtbs.push_back(info.dtb);
			}
		}
	}

	//loop over possible dtbs and set the config to use it til we find the correct one
	for (size_t i = 0; i < possible_dtbs.size(); i++)
	{
		auto dtb = possible_dtbs[i];
		VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_PROCESS_DTB | processID, dtb);
		result = VMMDLL_Map_GetModuleFromNameU(hVMM, processID, name, &module_entry, NULL);
		if (result)
		{
			DWORD readsize;
			this->BaseAddr = module_entry->vaBase;
			printf("[+] Imagebase: %lx\n", this->BaseAddr);
			return true;
		}
	}

	printf("[-] Failed to patch module\n");
	return false;
}

bool Memory::Read(uintptr_t address, void* buffer, size_t size) const
{
	DWORD read_size = 0;
	if (!VMMDLL_MemReadEx(hVMM, this->ProcessID, address, static_cast<PBYTE>(buffer), size, &read_size, VMMDLL_FLAG_NOCACHE))
	{
		printf("[!] Failed to read Memory at 0x%p\n", address);
		return false;
	}

	return (read_size == size);
}

bool Memory::Write(uintptr_t address, void* buffer, size_t size) const
{
	if (!VMMDLL_MemWrite(hVMM, this->ProcessID, address, static_cast<PBYTE>(buffer), size))
	{
		printf("[!] Failed to write Memory at 0x%p\n", address);
		return false;
	}
	return true;
}

bool Memory::OpenProcess(const char *name)
{
	DWORD pid = 0;
	if (!VMMDLL_PidGetFromName(hVMM, name, &pid))
	{
		return false;
	}

	if (!pid)
	{
		return false;
	}

	if (!FixDtb(pid, name))
	{
		return false;
	}

	ProcessID = pid;
	return true;
}

void Memory::DumpProcess()
{
    _IMAGE_DOS_HEADER dosHeader;
	this->Read(this->BaseAddr, &dosHeader, sizeof(dosHeader));

	_IMAGE_NT_HEADERS ntHeaders;
	this->Read(this->BaseAddr + dosHeader.e_lfanew, &ntHeaders, sizeof(_IMAGE_NT_HEADERS));

	printf("section alignment : %d\n", ntHeaders.OptionalHeader.SectionAlignment);
	printf("file alignment : %d\n", ntHeaders.OptionalHeader.FileAlignment);
	printf("number of sections : %d\n", ntHeaders.FileHeader.NumberOfSections);

	int dosStubSize = dosHeader.e_lfanew - sizeof(_IMAGE_DOS_HEADER);
	char *dosStub = new char[dosStubSize];
	this->Read(this->BaseAddr + sizeof(_IMAGE_DOS_HEADER), dosStub, dosStubSize);

	uintptr_t sectionHeaderOff = this->BaseAddr + dosHeader.e_lfanew + 0x18 + ntHeaders.FileHeader.SizeOfOptionalHeader;

	struct SectionChunk
	{
		_IMAGE_SECTION_HEADER *sectionHeader;
		char *sectionData;
		unsigned int size;
	};

	std::vector<SectionChunk> chunks;

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		_IMAGE_SECTION_HEADER *sectionHeaderLocal = new _IMAGE_SECTION_HEADER;
		this->Read(sectionHeaderOff, sectionHeaderLocal, sizeof(_IMAGE_SECTION_HEADER));

		char *readData = nullptr;

		unsigned int readSize = sectionHeaderLocal->Misc.VirtualSize;
		unsigned int changedReadSize = 0;

		if (readSize != 0)
		{
			if (readSize <= 100)
			{
				changedReadSize = readSize;
				readData = new char[readSize];

				this->Read(this->BaseAddr + sectionHeaderLocal->VirtualAddress, &readData, readSize);
			}
			else
			{
				uintptr_t sectionPointer = this->BaseAddr + sectionHeaderLocal->VirtualAddress;

				unsigned int currentReadSize = readSize % 100;

				if (currentReadSize == 0)
				{
					currentReadSize = 100;
				}

				uintptr_t currentOffset = sectionPointer + readSize - currentReadSize;

				while (currentOffset >= sectionPointer)
				{
					char *buffer = new char[currentReadSize];

					this->Read(currentOffset, buffer, currentReadSize);

					auto getInstructionCount = [](char *buffer, size_t len)
					{
						for (size_t i = len - 1; i >= 0; i--)
						{
							if (buffer[i] > 0)
							{
								return i + 1;
							}
						}

						return 0ul;
					};

					size_t codeByteCount = getInstructionCount(buffer, currentReadSize);

					if (codeByteCount != 0)
					{
						currentOffset += codeByteCount;

						if (sectionPointer < currentOffset)
						{
							changedReadSize = currentOffset - sectionPointer;
							changedReadSize += 4;

							if (readSize < changedReadSize)
							{
								changedReadSize = readSize;
							}
						}

						break;
					}

					currentReadSize = 100;
					currentOffset -= currentReadSize;
				}

				if (changedReadSize != 0)
				{
					readData = new char[changedReadSize];

					this->Read(this->BaseAddr + sectionHeaderLocal->VirtualAddress, readData, changedReadSize);
				}
			}
		}

		chunks.push_back(
			{sectionHeaderLocal,
			 readData,
			 changedReadSize
			});

		sectionHeaderOff += sizeof(_IMAGE_SECTION_HEADER);
	}

	for (int i = 0; i < chunks.size(); i++)
	{
		printf("section %d size of data : 0x%lx\n", i, chunks[i].sectionHeader->SizeOfRawData);
	}

	std::sort(chunks.begin(), chunks.end(),
			  [&](const SectionChunk &lhs, const SectionChunk &rhs)
			  {
				  return lhs.sectionHeader->PointerToRawData < rhs.sectionHeader->PointerToRawData;
			  });

	const auto alignValue = [](unsigned int value, unsigned int alignment)
	{
		return ((value + alignment - 1) / alignment) * alignment;
	};

	unsigned int newFileSize = dosHeader.e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader + (ntHeaders.FileHeader.NumberOfSections * sizeof(_IMAGE_SECTION_HEADER));

	for (int i = 0; i < chunks.size(); i++)
	{
		chunks[i].sectionHeader->VirtualAddress = alignValue(chunks[i].sectionHeader->VirtualAddress, ntHeaders.OptionalHeader.SectionAlignment);
		chunks[i].sectionHeader->Misc.VirtualSize = alignValue(chunks[i].sectionHeader->Misc.VirtualSize, ntHeaders.OptionalHeader.SectionAlignment);
		chunks[i].sectionHeader->PointerToRawData = alignValue(newFileSize, ntHeaders.OptionalHeader.FileAlignment);
		chunks[i].sectionHeader->SizeOfRawData = alignValue(chunks[i].size, ntHeaders.OptionalHeader.FileAlignment);

		newFileSize = (unsigned int)(chunks[i].sectionHeader->PointerToRawData + chunks[i].sectionHeader->SizeOfRawData);
	}

	std::sort(chunks.begin(), chunks.end(),
			  [&](const SectionChunk &lhs, const SectionChunk &rhs)
			  {
				  return lhs.sectionHeader->VirtualAddress < rhs.sectionHeader->VirtualAddress;
			  });

	ntHeaders.OptionalHeader.DataDirectory[11].VirtualAddress = 0;
	ntHeaders.OptionalHeader.DataDirectory[11].Size = 0;

	for (int i = ntHeaders.OptionalHeader.NumberOfRvaAndSizes; i < 16; i++)
	{
		ntHeaders.OptionalHeader.DataDirectory[i].VirtualAddress = 0;
		ntHeaders.OptionalHeader.DataDirectory[i].Size = 0;
	}

	ntHeaders.OptionalHeader.NumberOfRvaAndSizes = 16;
	ntHeaders.FileHeader.SizeOfOptionalHeader = sizeof(_IMAGE_OPTIONAL_HEADER);

	unsigned int lastSize = 0;

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		if (chunks[i].sectionHeader->VirtualAddress + chunks[i].sectionHeader->Misc.VirtualSize > lastSize)
		{
			lastSize = chunks[i].sectionHeader->VirtualAddress + chunks[i].sectionHeader->Misc.VirtualSize;
		}
	}

	ntHeaders.OptionalHeader.SizeOfImage = lastSize;

	unsigned int size = dosHeader.e_lfanew + 0x4 + sizeof(_IMAGE_FILE_HEADER);
	ntHeaders.OptionalHeader.SizeOfHeaders = alignValue(size + ntHeaders.FileHeader.SizeOfOptionalHeader + (ntHeaders.FileHeader.NumberOfSections * sizeof(_IMAGE_SECTION_HEADER)), ntHeaders.OptionalHeader.FileAlignment);

	unsigned int iatDataAddr = ntHeaders.OptionalHeader.DataDirectory[12].VirtualAddress;

	ntHeaders.OptionalHeader.DataDirectory[12].VirtualAddress = 0;
	ntHeaders.OptionalHeader.DataDirectory[12].Size = 0;

	if (iatDataAddr != 0)
	{
		for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
		{
			if (chunks[i].sectionHeader->VirtualAddress <= iatDataAddr && chunks[i].sectionHeader->VirtualAddress + chunks[i].sectionHeader->Misc.VirtualSize > iatDataAddr)
			{
				chunks[i].sectionHeader->Characteristics |= 0x40000000 | 0x80000000;
			}
		}
	}

	std::remove("out_dump.bin");
	std::ofstream file("out_dump.bin", std::ios::binary | std::ios::app);

	// dos header
	file.write((char *)&dosHeader.e_magic, sizeof(dosHeader.e_magic));
	file.write((char *)&dosHeader.e_cblp, sizeof(dosHeader.e_cblp));
	file.write((char *)&dosHeader.e_cp, sizeof(dosHeader.e_cp));
	file.write((char *)&dosHeader.e_crlc, sizeof(dosHeader.e_crlc));
	file.write((char *)&dosHeader.e_cparhdr, sizeof(dosHeader.e_cparhdr));
	file.write((char *)&dosHeader.e_minalloc, sizeof(dosHeader.e_minalloc));
	file.write((char *)&dosHeader.e_maxalloc, sizeof(dosHeader.e_maxalloc));
	file.write((char *)&dosHeader.e_ss, sizeof(dosHeader.e_ss));
	file.write((char *)&dosHeader.e_sp, sizeof(dosHeader.e_sp));
	file.write((char *)&dosHeader.e_csum, sizeof(dosHeader.e_csum));
	file.write((char *)&dosHeader.e_ip, sizeof(dosHeader.e_ip));
	file.write((char *)&dosHeader.e_cs, sizeof(dosHeader.e_cs));
	file.write((char *)&dosHeader.e_lfarlc, sizeof(dosHeader.e_lfarlc));
	file.write((char *)&dosHeader.e_ovno, sizeof(dosHeader.e_ovno));

	for (int i = 0; i < 4; i++)
	{
		file.write((char *)&dosHeader.e_res[i], sizeof(dosHeader.e_res[i]));
	}

	file.write((char *)&dosHeader.e_oemid, sizeof(dosHeader.e_oemid));
	file.write((char *)&dosHeader.e_oeminfo, sizeof(dosHeader.e_oeminfo));

	for (int i = 0; i < 10; i++)
	{
		file.write((char *)&dosHeader.e_res2[i], sizeof(dosHeader.e_res2[i]));
	}

	file.write((char *)&dosHeader.e_lfanew, sizeof(dosHeader.e_lfanew));

	// dos stub
	file.write(dosStub, dosStubSize);

	// pe header
	file.write((char *)&ntHeaders.Signature, sizeof(ntHeaders.Signature));

	// pe file header
	file.write((char *)&ntHeaders.FileHeader.Machine, sizeof(ntHeaders.FileHeader.Machine));
	file.write((char *)&ntHeaders.FileHeader.NumberOfSections, sizeof(ntHeaders.FileHeader.NumberOfSections));
	file.write((char *)&ntHeaders.FileHeader.TimeDateStamp, sizeof(ntHeaders.FileHeader.TimeDateStamp));
	file.write((char *)&ntHeaders.FileHeader.PointerToSymbolTable, sizeof(ntHeaders.FileHeader.PointerToSymbolTable));
	file.write((char *)&ntHeaders.FileHeader.NumberOfSymbols, sizeof(ntHeaders.FileHeader.NumberOfSymbols));
	file.write((char *)&ntHeaders.FileHeader.SizeOfOptionalHeader, sizeof(ntHeaders.FileHeader.SizeOfOptionalHeader));
	file.write((char *)&ntHeaders.FileHeader.Characteristics, sizeof(ntHeaders.FileHeader.Characteristics));

	// pe optional header
	file.write((char *)&ntHeaders.OptionalHeader.Magic, sizeof(ntHeaders.OptionalHeader.Magic));
	file.write((char *)&ntHeaders.OptionalHeader.MajorLinkerVersion, sizeof(ntHeaders.OptionalHeader.MajorLinkerVersion));
	file.write((char *)&ntHeaders.OptionalHeader.MinorLinkerVersion, sizeof(ntHeaders.OptionalHeader.MinorLinkerVersion));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfCode, sizeof(ntHeaders.OptionalHeader.SizeOfCode));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfInitializedData, sizeof(ntHeaders.OptionalHeader.SizeOfInitializedData));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfUninitializedData, sizeof(ntHeaders.OptionalHeader.SizeOfUninitializedData));
	file.write((char *)&ntHeaders.OptionalHeader.AddressOfEntryPoint, sizeof(ntHeaders.OptionalHeader.AddressOfEntryPoint));
	file.write((char *)&ntHeaders.OptionalHeader.BaseOfCode, sizeof(ntHeaders.OptionalHeader.BaseOfCode));

	file.write((char *)&ntHeaders.OptionalHeader.ImageBase, sizeof(ntHeaders.OptionalHeader.ImageBase));
	file.write((char *)&ntHeaders.OptionalHeader.SectionAlignment, sizeof(ntHeaders.OptionalHeader.SectionAlignment));
	file.write((char *)&ntHeaders.OptionalHeader.FileAlignment, sizeof(ntHeaders.OptionalHeader.FileAlignment));
	file.write((char *)&ntHeaders.OptionalHeader.MajorOperatingSystemVersion, sizeof(ntHeaders.OptionalHeader.MajorOperatingSystemVersion));
	file.write((char *)&ntHeaders.OptionalHeader.MinorOperatingSystemVersion, sizeof(ntHeaders.OptionalHeader.MinorOperatingSystemVersion));
	file.write((char *)&ntHeaders.OptionalHeader.MajorImageVersion, sizeof(ntHeaders.OptionalHeader.MajorImageVersion));
	file.write((char *)&ntHeaders.OptionalHeader.MinorImageVersion, sizeof(ntHeaders.OptionalHeader.MinorImageVersion));
	file.write((char *)&ntHeaders.OptionalHeader.MajorSubsystemVersion, sizeof(ntHeaders.OptionalHeader.MajorSubsystemVersion));
	file.write((char *)&ntHeaders.OptionalHeader.MinorSubsystemVersion, sizeof(ntHeaders.OptionalHeader.MinorSubsystemVersion));
	file.write((char *)&ntHeaders.OptionalHeader.Win32VersionValue, sizeof(ntHeaders.OptionalHeader.Win32VersionValue));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfImage, sizeof(ntHeaders.OptionalHeader.SizeOfImage));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfHeaders, sizeof(ntHeaders.OptionalHeader.SizeOfHeaders));
	file.write((char *)&ntHeaders.OptionalHeader.CheckSum, sizeof(ntHeaders.OptionalHeader.CheckSum));
	file.write((char *)&ntHeaders.OptionalHeader.Subsystem, sizeof(ntHeaders.OptionalHeader.Subsystem));
	file.write((char *)&ntHeaders.OptionalHeader.DllCharacteristics, sizeof(ntHeaders.OptionalHeader.DllCharacteristics));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfStackReserve, sizeof(ntHeaders.OptionalHeader.SizeOfStackReserve));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfStackCommit, sizeof(ntHeaders.OptionalHeader.SizeOfStackCommit));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfHeapReserve, sizeof(ntHeaders.OptionalHeader.SizeOfHeapReserve));
	file.write((char *)&ntHeaders.OptionalHeader.SizeOfHeapCommit, sizeof(ntHeaders.OptionalHeader.SizeOfHeapCommit));
	file.write((char *)&ntHeaders.OptionalHeader.LoaderFlags, sizeof(ntHeaders.OptionalHeader.LoaderFlags));
	file.write((char *)&ntHeaders.OptionalHeader.NumberOfRvaAndSizes, sizeof(ntHeaders.OptionalHeader.NumberOfRvaAndSizes));

	for (int i = 0; i < 16; i++)
	{
		file.write((char *)&ntHeaders.OptionalHeader.DataDirectory[i].VirtualAddress, sizeof(ntHeaders.OptionalHeader.DataDirectory[i].VirtualAddress));
		file.write((char *)&ntHeaders.OptionalHeader.DataDirectory[i].Size, sizeof(ntHeaders.OptionalHeader.DataDirectory[i].Size));
	}

	// sections (chunks)

	// headers
	for (int i = 0; i < chunks.size(); i++)
	{
		file.write((char *)&chunks[i].sectionHeader->Name, sizeof(chunks[i].sectionHeader->Name));
		file.write((char *)&chunks[i].sectionHeader->Misc.VirtualSize, sizeof(chunks[i].sectionHeader->Misc.VirtualSize));
		file.write((char *)&chunks[i].sectionHeader->VirtualAddress, sizeof(chunks[i].sectionHeader->VirtualAddress));
		file.write((char *)&chunks[i].sectionHeader->SizeOfRawData, sizeof(chunks[i].sectionHeader->SizeOfRawData));
		file.write((char *)&chunks[i].sectionHeader->PointerToRawData, sizeof(chunks[i].sectionHeader->PointerToRawData));
		file.write((char *)&chunks[i].sectionHeader->PointerToRelocations, sizeof(chunks[i].sectionHeader->PointerToRelocations));
		file.write((char *)&chunks[i].sectionHeader->PointerToLinenumbers, sizeof(chunks[i].sectionHeader->PointerToLinenumbers));
		file.write((char *)&chunks[i].sectionHeader->NumberOfRelocations, sizeof(chunks[i].sectionHeader->NumberOfRelocations));
		file.write((char *)&chunks[i].sectionHeader->NumberOfLinenumbers, sizeof(chunks[i].sectionHeader->NumberOfLinenumbers));
		file.write((char *)&chunks[i].sectionHeader->Characteristics, sizeof(chunks[i].sectionHeader->Characteristics));
	}

	size_t totalDataSz = 0;
	// data
	for (int i = 0; i < chunks.size(); i++)
	{
		const auto &sec = chunks[i];
		totalDataSz += sec.size;

		if (sec.sectionHeader->PointerToRawData > 0)
		{
			if (sec.sectionHeader->PointerToRawData > file.tellp())
			{
				unsigned int padding = sec.sectionHeader->PointerToRawData - file.tellp();
				char pad[padding];
				file.write(pad, padding);
			}
		}

		if (sec.size > 0)
		{
			file.write(sec.sectionData, sec.size);

			if (sec.size < sec.sectionHeader->SizeOfRawData)
			{
				unsigned int padding = sec.sectionHeader->SizeOfRawData - sec.size;
				char pad[padding];
				file.write(pad, padding);
			}
		}
	}

	printf("total chunks size : %ld\n", totalDataSz);

	printf("done\n");
}