#ifndef _PROCESSMONITOR_H_
#define _PROCESSMONITOR_H_

#include <string>
#include <vector>
#include <windows.h>
#include "Process.h"
#include "DynConfig.h"
#include "Utils.h"
#include "DebugLog.h"
#include "LoadLibraryR.h"

using namespace std;

#pragma comment(lib, "Advapi32.lib")

// Store process information in shared memory

#define MAX_PROCESS_NAME			256
#define MAX_PROCESSES_TO_TRACK		4096
#define SM_MUTEX_NAME				"NetRipperProcessMutex"
#define SM_SHARED_MEMORY_NAME		"NetRipperProcessesSM"
#define SM_SELF_REFLECTIVE_NAME		"SelfReflective"

struct PROCESS_SM_INFO
{
	DWORD Id = 0;
	char ProcessName[MAX_PROCESS_NAME] = { 0 };
};

// Monitor for new processes and inject DLL if needed

class ProcessMonitor
{
	static HANDLE s_Mutex;
	static void* s_pRawProcessMemory;
	static void* s_pRawSelfReflectiveMemory;
	static DWORD s_dwSelfReflectiveSize;
	static vector<string> s_vProcessToInjectList;

public:
	static void Init();
	static bool SelfReflectiveInject(DWORD p_dwProcessId);
	static void ProcessAdd(DWORD p_dwProcessId, string p_sProcessName);
	static void ProcessRemove(DWORD p_dwProcessId, string p_sProcessName);
	static bool ProcessExists(DWORD p_dwProcessId, string p_sProcessName);
	static void ProcessMonitorLoopThread();
};

#endif