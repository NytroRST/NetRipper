#ifndef _DYNCONFIG_H_
#define _DYNCONFIG_H_

#include <string>
#include <vector>
#include "DebugLog.h"
#include "Utils.h"

using namespace std;

#define MAX_CONFIG_SIZE 255

// Class used for dynamic configuration

class DynConfig
{
	static string s_sProcessNames;
	static string s_sProcessIDs;
	static string s_sPlugins;
	static string s_sDataPath;

	static string Filter(string p_sString);
	
public:

	static void Init();
	static vector<string> GetProcessNames();
	static vector<DWORD> GetProcessIDs();
	static vector<string> GetPlugins();
	static string GetDataPath();
};

#endif
