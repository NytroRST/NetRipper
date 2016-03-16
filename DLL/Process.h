
#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <string>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h> 
#include "Utils.h"
#include "DebugLog.h"

using namespace std;

// Struct for sections

struct SECTION_INFO
{
	DWORD dwStartAddress;
	DWORD dwSize;
};

// Struct for exports

struct EXPORT_ENTRY
{
	DWORD  dwAddress;
	DWORD  dwPointerOfAddress;
	string sName;
	USHORT uOrdinal;
};

// Process and PE stuff

class Process
{
public:
	static vector<MODULEENTRY32> GetProcessModules(DWORD p_dwID);
	static SECTION_INFO GetModuleSection(string p_sModule, string p_sSection);
	static DWORD SearchMemory(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize);
	static DWORD SearchMemoryByN(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize, unsigned int p_nN);
	static DWORD SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize);
};

#endif


