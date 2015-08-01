
#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>
#include <cstdio>
#include <sstream>
#include <vector>
#include "DebugLog.h"
#include "DynConfig.h"

using namespace std;

// Defines

#define MAX_TEMP_PATH 300

// Some useful stuff

class Utils
{
public:

	static string ToLower(string p_sString);
	static string ToPrintable(const char *p_pcString, size_t p_nLength);
	static string IntToString(unsigned int p_nNumer);
	static string IntToHex(unsigned int p_nNumer);
	static unsigned int StringToInt(string p_sNumer);
	static string GetFilename(string p_sFilename);
	static void WriteToTempFile(string p_sFilename, const unsigned char *p_pcBuffer, size_t p_nLength);
	static string GetStringBetween(string p_sString, string p_sStart, string p_sStop);
	static vector<string> SplitString(string p_sString, string p_sDelimiter);
};

#endif


