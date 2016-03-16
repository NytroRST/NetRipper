
#include "stdafx.h"
#include "Process.h"

// Search in memory

DWORD Process::SearchMemory(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize)
{
	unsigned char *pByte = (unsigned char *)p_pvStartAddress;

	for(size_t i = 0; i < p_dwSize - p_dwBufferSize; i++)
	{
		if(memcmp(pByte + i, p_pvBuffer, p_dwBufferSize) == 0)
		{
			return (DWORD)(pByte + i);
		}
	}

	DebugLog::Log("[ERROR] SearchMemory did not find the pattern!");

	return 0;
}

// Search in memory and return N'th occurence 

DWORD Process::SearchMemoryByN(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize, unsigned int p_nN)
{
	unsigned char *pByte = (unsigned char *)p_pvStartAddress;
	unsigned int n = 0;

	for(size_t i = 0; i < p_dwSize - p_dwBufferSize; i++)
	{
		// Find each occurence and return the N'th one

		if(memcmp(pByte + i, p_pvBuffer, p_dwBufferSize) == 0)
		{
			n++;
			if(n == p_nN) return (DWORD)(pByte + i);
		}
	}

	DebugLog::Log("[ERROR] SearchMemory did not find the pattern!");

	return 0;
}

// Seach a signature

DWORD Process::SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void *p_pvBuffer, DWORD p_dwBufferSize)
{
	DWORD dwMax = (DWORD)p_pvStartAddress + p_dwSize;
	unsigned char c1 = 0, c2 = 0;
	bool bOk = false;

	for(DWORD i = 0; i < p_dwSize - p_dwBufferSize; i++)
	{
		bOk = false;

		for(DWORD j = 0; j < p_dwBufferSize; j++)
		{
			// c1 = from memory, c2 = from signature
			
			c1 = *(unsigned char *)((DWORD)p_pvStartAddress + i + j);
			c2 = *(unsigned char *)((DWORD)p_pvBuffer + j);

			// Check character

			if(c1 == c2 || c2 == '?') 
			{
				bOk = true;
				continue;
			}
			else
			{
				bOk = false;
				break;
			}
		}

		// Check if we found the signature

		if(bOk) return (DWORD)p_pvStartAddress + i;
	}

	DebugLog::Log("[ERROR] SearchSignature did not find the signature!");

	return 0;
}

// Function returns a section data from a modules

SECTION_INFO Process::GetModuleSection(string p_sModule, string p_sSection)
{
	SECTION_INFO oSectionData = {0, 0};
	bool bFound = 0;

	// Check if module is loaded

	p_sModule = Utils::ToLower(p_sModule);
	vector<MODULEENTRY32> vModules = Process::GetProcessModules(0);

	for(size_t i = 0; i < vModules.size(); i++)
	{
		if(p_sModule.compare(Utils::ToLower(vModules[i].szModule)) == 0)
		{
			bFound = 1;

			HMODULE hModule = GetModuleHandle(vModules[i].szModule);

			// If we can get module handle

			if(hModule == NULL)
			{
				DebugLog::LogString("[ERROR] Cannot find module handle: ", p_sModule);
				return oSectionData;
			}

			// Parse module

			IMAGE_DOS_HEADER dos;
			IMAGE_NT_HEADERS ntHeaders;
			IMAGE_SECTION_HEADER *pSections = NULL;

			// Get DOS/PE header

			memcpy(&dos, (void *)hModule, sizeof(IMAGE_DOS_HEADER));
			memcpy(&ntHeaders, (void *)((DWORD)hModule + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS));

			// Get sections

			pSections = new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections];

			if(pSections == NULL)
			{
				DebugLog::LogInt("[ERROR] Cannot allocate space for sections: ", ntHeaders.FileHeader.NumberOfSections);
				return oSectionData;
			}

			// Copy

			memcpy(pSections, (void *)((DWORD)hModule + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS)), 
				(ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));

			// Print

			for(size_t j = 0; j < ntHeaders.FileHeader.NumberOfSections; j++)
			{
				if(p_sSection.compare((char *)pSections[j].Name) == 0)
				{
					oSectionData.dwSize = pSections[j].SizeOfRawData;
					oSectionData.dwStartAddress = (DWORD)hModule +  pSections[j].VirtualAddress;

					return oSectionData;
				}
			}
		}
	}

	DebugLog::LogString("[ERROR] GetModuleSection did not find the section: ", p_sSection);

	return oSectionData;
}

// Function that returns a vector with all modules from a process

vector<MODULEENTRY32> Process::GetProcessModules(DWORD p_dwID)
{
	HANDLE hSnapshot;
	MODULEENTRY32 hModule;
	vector<MODULEENTRY32> vModules;

	// Process ID = 0 or -1 => current process

	if(p_dwID == 0 || p_dwID == -1) p_dwID = GetCurrentProcessId();
	
	/* Get processes snapshot */
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p_dwID);
	
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		DebugLog::Log("[ERROR] Cannot get modules snapshot!");
		return vModules;
	}
	
	hModule.dwSize = sizeof(MODULEENTRY32); 
	
	// Get first process
	
	if(!Module32First(hSnapshot, &hModule))
	{
		DebugLog::Log("[ERROR] Cannot get first module!");
		return vModules;
	}
	
	vModules.push_back(hModule);
	
	// Get all processes
	
	while(Module32Next(hSnapshot, &hModule)) 
		vModules.push_back(hModule);

	return vModules;
}
