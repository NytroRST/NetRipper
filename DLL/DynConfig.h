#ifndef _DYNCONFIG_H_
#define _DYNCONFIG_H_

#include <string>
#include "DebugLog.h"
#include "Utils.h"

using namespace std;

#define MAX_CONFIG_SIZE 255

// Class used for dynamic configuration

class DynConfig
{
	static string s_sDataPath;
	static string s_sPlainText;
	static string s_sDataLimit;
	static string s_sStringFinder;

	static string Filter(string p_sString);
	
public:

	static void Init();
	static string GetDataPath();
	static string GetPlainText();
	static string GetDataLimit();
	static string GetStringFinder();
};

#endif
