#pragma once

#include <leechcore.h>
#include <vmmdll.h>
#include <cstring>
#include <stdio.h>
#include <memory>
#include <cstdint>

inline VMM_HANDLE hVMM = NULL;

class Memory
{
private:
    QWORD BaseAddr;
    int ProcessID;

    bool FixDtb(DWORD processID, const char *name);
    bool Read(uintptr_t address, void* buffer, size_t size) const;
    bool Write(uintptr_t address, void* buffer, size_t size) const;
public:
	~Memory() = default;
    
    bool OpenProcess(const char *name);
    void DumpProcess();
};