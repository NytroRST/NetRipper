
#include "stdafx.h"
#include "ProcessMonitor.h"

// Class data

HANDLE ProcessMonitor::s_Mutex = NULL;
void* ProcessMonitor::s_pRawProcessMemory = NULL;
void* ProcessMonitor::s_pRawSelfReflectiveMemory = NULL;
DWORD ProcessMonitor::s_dwSelfReflectiveSize = 0;
vector<string> ProcessMonitor::s_vProcessToInjectList;

// Init: Create mutex if not exists, create processes shared memory

void ProcessMonitor::Init()
{
	HANDLE hSharedMemory = NULL;
	HANDLE hSelfReflectiveMemory = NULL;
	bool bSMAlreadyExists = false;

	// Create Mutex if not exists or open it if it exists

	s_Mutex = CreateMutex(NULL, false, SM_MUTEX_NAME);
	bSMAlreadyExists = GetLastError() == ERROR_ALREADY_EXISTS;

	if (s_Mutex == NULL)
	{
		DebugLog::Log("Error: Cannot create or open the mutex!");
		return;
	}

	// Create shared memory for processes if it does not exist and get pointer to raw memory

	if(bSMAlreadyExists) hSharedMemory = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, SM_SHARED_MEMORY_NAME);
	else hSharedMemory = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(DWORD) + sizeof(PROCESS_SM_INFO) * MAX_PROCESSES_TO_TRACK, SM_SHARED_MEMORY_NAME);

	if (hSharedMemory == NULL)
	{
		DebugLog::Log("Error: Cannot create or open the shared memory for processes!");
		return;
	}
	
	s_pRawProcessMemory = MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(DWORD) + sizeof(PROCESS_SM_INFO) * MAX_PROCESSES_TO_TRACK);

	if (s_pRawProcessMemory == NULL)
	{
		DebugLog::Log("Error: Cannot get the raw memory of the shared processes!");
		return;
	}

	// Init the number of processes in the shared memory

	if (!bSMAlreadyExists) *(DWORD*)s_pRawProcessMemory = 0;

	DebugLog::LogInt("Nr. of processes: ", *(DWORD*)s_pRawProcessMemory);

	// Open self reflective memory and get pointer to raw memory

	hSelfReflectiveMemory = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, SM_SELF_REFLECTIVE_NAME);

	if (hSelfReflectiveMemory == NULL)
	{
		DebugLog::Log("Cannot open the shared memory for self reflective DLL!");
		return;
	}

	s_pRawSelfReflectiveMemory = MapViewOfFile(hSelfReflectiveMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(DWORD));
	if (s_pRawSelfReflectiveMemory == NULL)
	{
		DebugLog::Log("Cannot get the size of the raw memory of the selft reflective DLL!");
		return;
	}

	CopyMemory(&s_dwSelfReflectiveSize, s_pRawSelfReflectiveMemory, sizeof(DWORD));
	UnmapViewOfFile(s_pRawSelfReflectiveMemory);

	s_pRawSelfReflectiveMemory = MapViewOfFile(hSelfReflectiveMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(DWORD) + s_dwSelfReflectiveSize);
	if (s_pRawSelfReflectiveMemory == NULL)
	{
		DebugLog::Log("Cannot get the raw memory of the selft reflective DLL!");
		return;
	}

	MoveMemory(s_pRawSelfReflectiveMemory, (unsigned char *)s_pRawSelfReflectiveMemory + sizeof(DWORD), s_dwSelfReflectiveSize);

	CloseHandle(hSelfReflectiveMemory);

	// Get list of processes to inject it

	string sProcessList = DynConfig::GetProcessList();

	if (sProcessList.length() == 0) DebugLog::Log("No processes defined for auto injection!");
	else s_vProcessToInjectList = Utils::SplitString(sProcessList, ",");

	// Assume currently specified process names are already injected, so add them to the list

	DWORD dwWaitResult = WaitForSingleObject(s_Mutex, INFINITE);

	if (dwWaitResult == WAIT_OBJECT_0)
	{
		vector<PROCESS_TO_MONITOR> vRunningProcesses = Process::GetProcesses();

		for (size_t i = 0; i < vRunningProcesses.size(); i++)
		{
			for (size_t j = 0; j < s_vProcessToInjectList.size(); j++)
			{
				if (vRunningProcesses[i].ProcessName.compare(s_vProcessToInjectList[j]) == 0)
					ProcessAdd(vRunningProcesses[i].Id, vRunningProcesses[i].ProcessName);
			}
		}

		ReleaseMutex(s_Mutex);
	}

	// And create the loop thread

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProcessMonitorLoopThread, NULL, 0, NULL);

	if (hThread == NULL) DebugLog::Log("Error: Could not create process monitoring thread!");
}

// Will self reflective inject the DLL
// Adaptation of the original version from Inject.c of ReflectiveDLL project
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/Inject.c 

bool ProcessMonitor::SelfReflectiveInject(DWORD p_dwProcessId)
{
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	// To check for 32/64 bits!
	BOOL bIs32Bit = FALSE;

	// Adjust privileges

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	// Open target process

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, p_dwProcessId);

	if (!hProcess)
	{
		DebugLog::LogInt("Error: Failed to open the target process for self reflective injection: ", p_dwProcessId);
		return false;
	}

	// Inject reflective DLL

	hModule = LoadRemoteLibraryR(hProcess, s_pRawSelfReflectiveMemory, s_dwSelfReflectiveSize, NULL);

	if (!hModule)
	{
		DebugLog::LogInt("Error: Failed to inject the DLL in process: ", p_dwProcessId);
		return false;
	}

	WaitForSingleObject(hModule, -1);

	// Cleanup

	if (hProcess)
		CloseHandle(hProcess);

	return true;
}

// Add a process to the shared memory

void ProcessMonitor::ProcessAdd(DWORD p_dwProcessId, string p_sProcessName)
{
	PROCESS_SM_INFO pi;

	if (p_dwProcessId == 0 || p_sProcessName.length() == 0 || p_sProcessName.length() > 255)
	{
		DebugLog::Log("Invalid process to add!");
		return;
	}

	// Do not add if it already exists

	if (ProcessExists(p_dwProcessId, p_sProcessName)) return;
	
	pi.Id = p_dwProcessId;
	CopyMemory(pi.ProcessName, p_sProcessName.c_str(), p_sProcessName.length());
	pi.ProcessName[p_sProcessName.length()] = '\0';

	// Add structure at the end of the buffer (if space is OK)

	if (*(DWORD*)s_pRawProcessMemory < MAX_PROCESSES_TO_TRACK)
	{
		CopyMemory((unsigned char*)s_pRawProcessMemory + sizeof(DWORD) + *(DWORD*)s_pRawProcessMemory * sizeof(PROCESS_SM_INFO), &pi, sizeof(PROCESS_SM_INFO));
		*(DWORD*)s_pRawProcessMemory = *(DWORD*)s_pRawProcessMemory + 1;
		DebugLog::LogInt("Added new process: ", p_dwProcessId);
		DebugLog::LogString("Added new process: ", p_sProcessName);
	}
	else DebugLog::Log("Cannot add a new process, maximum reached!");
}

// Remove a process from the shared memory

void ProcessMonitor::ProcessRemove(DWORD p_dwProcessId, string p_sProcessName)
{
	PROCESS_SM_INFO* ppi = NULL;

	if (p_dwProcessId == 0 || p_sProcessName.length() == 0 || p_sProcessName.length() > 255)
	{
		DebugLog::Log("Invalid process to delete!");
		return;
	}

	if (!ProcessExists(p_dwProcessId, p_sProcessName))
	{
		DebugLog::LogInt("Cannot remove process because it does not exists in the list: ", p_dwProcessId);
		return;
	}

	// Find the existing process 

	for (size_t i = 0; i < *(DWORD*)s_pRawProcessMemory; i++)
	{
		ppi = (PROCESS_SM_INFO*)((unsigned char*)s_pRawProcessMemory + sizeof(DWORD) + i * sizeof(PROCESS_SM_INFO));
		if (ppi->Id == p_dwProcessId && p_sProcessName.compare(ppi->ProcessName) == 0)
		{
			// If the process is not the last one

			if (i < *(DWORD*)s_pRawProcessMemory - 1)
			{
				MoveMemory(((unsigned char*)s_pRawProcessMemory + sizeof(DWORD) + i * sizeof(PROCESS_SM_INFO)),
					((unsigned char*)s_pRawProcessMemory + sizeof(DWORD) + (*(DWORD*)s_pRawProcessMemory - 1) * sizeof(PROCESS_SM_INFO)),
					sizeof(PROCESS_SM_INFO));
				DebugLog::LogInt("Process removed from the list: ", p_dwProcessId);
			}

			*(DWORD*)s_pRawProcessMemory = *(DWORD*)s_pRawProcessMemory - 1;
			break;
		}
	}
}

// Check if a process exists in the shared memory

bool ProcessMonitor::ProcessExists(DWORD p_dwProcessId, string p_sProcessName)
{
	PROCESS_SM_INFO* ppi = NULL;
	
	if (p_dwProcessId == 0 || p_sProcessName.length() == 0 || p_sProcessName.length() > 255)
	{
		DebugLog::Log("Invalid process to check if it exists!");
		return false;
	}

	for (size_t i = 0; i < *(DWORD*)s_pRawProcessMemory; i++)
	{
		ppi = (PROCESS_SM_INFO*)((unsigned char*)s_pRawProcessMemory + sizeof(DWORD) + i * sizeof(PROCESS_SM_INFO));

		if (ppi->Id == p_dwProcessId && p_sProcessName.compare(ppi->ProcessName) == 0) return true;
	}

	return false;
}

// Runs in a new thread, monitors for new processes and do everything needed

void ProcessMonitor::ProcessMonitorLoopThread()
{
	DWORD dwWaitResult = 0;
	PROCESS_SM_INFO* ppi = NULL;

	while (true)
	{
		dwWaitResult = WaitForSingleObject(s_Mutex, INFINITE);

		// If we got access to the queue

		if (dwWaitResult == WAIT_OBJECT_0)
		{
			vector<PROCESS_TO_MONITOR> vRunningProcesses = Process::GetProcesses();

			// Check for new process

			for (size_t i = 0; i < vRunningProcesses.size(); i++)
			{
				for (size_t j = 0; j < s_vProcessToInjectList.size(); j++)
				{
					if (vRunningProcesses[i].ProcessName.compare(s_vProcessToInjectList[j]) == 0)
					{
						// New process which does not exist, inject and add it to the list

						if (!ProcessExists(vRunningProcesses[i].Id, vRunningProcesses[i].ProcessName))
						{
							ProcessAdd(vRunningProcesses[i].Id, vRunningProcesses[i].ProcessName);

							DebugLog::LogInt("New process found, selft injecting to: ", vRunningProcesses[i].Id);
							SelfReflectiveInject(vRunningProcesses[i].Id);
						}
					}
				}
			}

			// Check for process to remove

			for (size_t i = 0; i < *(DWORD*)s_pRawProcessMemory; i++)
			{
				ppi = (PROCESS_SM_INFO*)((unsigned char*)s_pRawProcessMemory + sizeof(DWORD) + i * sizeof(PROCESS_SM_INFO));
				bool bFound = false;

				for (size_t j = 0; j < vRunningProcesses.size(); j++)
				{
					if (vRunningProcesses[j].Id == ppi->Id && vRunningProcesses[j].ProcessName.compare(ppi->ProcessName) == 0) bFound = true;
				}

				if (bFound == false)
				{
					ProcessRemove(ppi->Id, ppi->ProcessName);
					DebugLog::LogInt("Process not running anymore, removing from the list: ", ppi->Id);
				}
			}

			// Small sleep to not stress the CPU

			ReleaseMutex(s_Mutex);
			Sleep(100);
		}

		// Probably the process that created the mutex no longer exists

		else if (dwWaitResult == WAIT_ABANDONED)
		{
			s_Mutex = CreateMutex(NULL, false, SM_MUTEX_NAME);
			DebugLog::LogInt("An error occured with the Mutex, recreating it: ", dwWaitResult);
		}

		// Pretty sure something is not right

		else
		{
			DebugLog::LogInt("An error occured with the Mutex, returning from thread!", dwWaitResult);
			return;
		}
	}
}

