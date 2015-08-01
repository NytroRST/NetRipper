
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

// Function that returns a pointer to a function from a DLL

DWORD Process::GetFunctionAddress(string p_sFuncName, string p_sDLLName)
{
	HMODULE hModule;
	FARPROC pFN;
	
	// Get module
	
	hModule = GetModuleHandle(p_sDLLName.c_str());
	
	if(hModule == NULL)
	{
		string sDebug = "[ERROR] Cannot get DLL handle: ";
		sDebug = sDebug + p_sDLLName;
		DebugLog::Log(sDebug);

		return 0;
	}
	
	// Get function
	
	pFN = GetProcAddress(hModule, p_sFuncName.c_str());
	
	if(pFN == NULL) 
	{
		string sDebug = "[ERROR] Cannot get DLL function address: ";
		sDebug = sDebug + p_sDLLName;
		sDebug = sDebug + " : ";
		sDebug = sDebug + p_sFuncName;

		DebugLog::Log(sDebug);
		
		return 0;
	}

	else return (DWORD)pFN;
}

// Function returns a vector of exports for a specified DLL

vector<EXPORT_ENTRY> Process::GetDLLExports(string p_sModule)
{
	vector<EXPORT_ENTRY> vExports;
	BYTE *pcImageBase = NULL;
	HMODULE hResult = NULL;
	
	// Make sure library is loaded 

	hResult = GetModuleHandle(p_sModule.c_str());

	if(hResult == NULL)
	{
		DebugLog::LogString("[ERROR] Cannot get DLL handle: ", p_sModule);
		
		// Forcely load DLL, ugly but we make sure the DLL functions are hooked

		LoadLibrary(p_sModule.c_str());
	}

	// Get modules 
	
	vector<MODULEENTRY32> vModules = GetProcessModules(0);
	
	if(vModules.size() == 0)
	{
		DebugLog::LogString("[ERROR] Cannot get current process modules, searching for: ", p_sModule);
		return vExports;
	}

	// Case insensitive

	p_sModule = Utils::ToLower(p_sModule);
	
	// Find requested module
	
	for(size_t i = 0; i < vModules.size(); i++)
	{
		if(p_sModule.compare(Utils::ToLower(vModules[i].szModule)) == 0)
		{
			pcImageBase = vModules[i].modBaseAddr;

			// Parse PE headers
			
			IMAGE_DOS_HEADER oDOS;
			IMAGE_NT_HEADERS oNT;
			IMAGE_DATA_DIRECTORY oExportDirEntry;
			IMAGE_EXPORT_DIRECTORY oExportDirectory;
			
			// Parse EAT
			
			DWORD *pdwAddressOfFunctions = NULL;
			DWORD *pdwAddressOfNames = NULL;
			
			CHAR *pcFunctionName = NULL;
			DWORD dwFunctionAddress = 0;
			
			DWORD dwFunctionPointerLocation = 0;
			
			// Get Export directory
			
			memcpy(&oDOS, pcImageBase, sizeof(oDOS));
			memcpy(&oNT, (BYTE *)((DWORD)pcImageBase + oDOS.e_lfanew), sizeof(oNT));
			oExportDirEntry = oNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			memcpy(&oExportDirectory, (BYTE *)((DWORD)pcImageBase + oExportDirEntry.VirtualAddress), sizeof(oExportDirectory));
			
			// Parse names
			
			pdwAddressOfNames     = (DWORD *)((DWORD)pcImageBase + oExportDirectory.AddressOfNames);
			pdwAddressOfFunctions = (DWORD *)((DWORD)pcImageBase + oExportDirectory.AddressOfFunctions);
			
			for(DWORD nr = 0; nr < oExportDirectory.NumberOfFunctions; nr++)
			{
				EXPORT_ENTRY oExport;
				
				// Get function details
				
				pcFunctionName            = (CHAR *)((DWORD)pcImageBase + (DWORD)(pdwAddressOfNames[nr]));
				dwFunctionAddress         = (DWORD)pcImageBase + (DWORD)(pdwAddressOfFunctions[nr]);
				dwFunctionPointerLocation = (DWORD)pcImageBase + oExportDirectory.AddressOfFunctions + nr * sizeof(DWORD);
				
				// Save new function export
				
				oExport.dwAddress          = dwFunctionAddress;
				oExport.dwPointerOfAddress = dwFunctionPointerLocation;
				oExport.sName              = pcFunctionName;
				oExport.uOrdinal           = (USHORT)nr + 1;
				
				vExports.push_back(oExport);
			}
			
			// Do not care about other modules
			
			break;
		}
	}
	
	return vExports;
}
