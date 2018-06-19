
#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h> 
#include "Utils.h"
#include "DebugLog.h"

using namespace std;

// Address type

#if defined _M_X64
#define ADDRESS_VALUE uint64_t
#elif defined _M_IX86
#define ADDRESS_VALUE uint32_t
#endif

// Struct for sections

struct SECTION_INFO
{
	ADDRESS_VALUE dwStartAddress;
	DWORD dwSize;
};

// Struct for exports

struct EXPORT_ENTRY
{
	ADDRESS_VALUE dwAddress;
	ADDRESS_VALUE dwPointerOfAddress;
	string sName;
	USHORT uOrdinal;
};

// Process and PE stuff

class Process
{
public:
	static vector<MODULEENTRY32> GetProcessModules(DWORD p_dwID);
	static SECTION_INFO GetModuleSection(string p_sModule, string p_sSection);
	static ADDRESS_VALUE SearchMemory(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize);
	static ADDRESS_VALUE SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize);
};

#endif


