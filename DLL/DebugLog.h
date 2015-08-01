
#ifndef _DEBUGLOG_H_
#define _DEBUGLOG_H_

#include <string>
#include <cstdio>
#include "Utils.h"
#include "DynConfig.h"

using namespace std;

#define MAX_TEMP_PATH 300

// Class used for Debug

class DebugLog
{
	static string s_sFolder;
	static string s_sFilename;
	static bool s_bAddProcessID;
	
public:

	static void Init();

	static void Log(string p_sData);
	static void Log(const char *p_pc_Data, unsigned int p_nLength);

	static void LogString(string p_sData, string p_sString);
	static void LogInt(string p_sData, DWORD p_dwInt);
	static void LogIntHex(string p_sData, DWORD p_dwInt);

	static void DebugError(string p_sString);

	static void UseProcessID() { s_bAddProcessID = true; }
	static void DoNotUseProcessID() { s_bAddProcessID = false; }
};

#endif
