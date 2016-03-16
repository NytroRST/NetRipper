
#include "stdafx.h"
#include "DebugLog.h"

string DebugLog::s_sFolder       = "";
string DebugLog::s_sFilename     = "NetRipperLog.txt";
bool   DebugLog::s_bAddProcessID = false;

// Initialization

void DebugLog::Init()
{
	s_sFolder = DynConfig::GetDataPath();
}

// Log string

void DebugLog::Log(string p_sData)
{
	DebugLog::Log(p_sData.c_str(), p_sData.length());
}

// Log info with a string

void DebugLog::LogString(string p_sData, string p_sString)
{
	string sStr = p_sData;
	sStr = sStr + p_sString;

	DebugLog::Log(sStr);
}

// Log an info string and an int

void DebugLog::LogInt(string p_sData, DWORD p_dwInt)
{
	string sStr = p_sData;
	sStr = sStr + Utils::IntToString(p_dwInt);

	DebugLog::Log(sStr);
}

// Log an info string and an int hex

void DebugLog::LogIntHex(string p_sData, DWORD p_dwInt)
{
	string sStr = p_sData;
	sStr = sStr + Utils::IntToHex(p_dwInt);

	DebugLog::Log(sStr);
}

// Log data to specified file

void DebugLog::Log(const char *p_pc_Data, unsigned int p_nLength)
{
	string sFilename = DebugLog::s_sFolder;
	FILE *pFile = NULL;
	size_t nWritten = 0;

	// Add process ID?

	if(DebugLog::s_bAddProcessID == true)
	{
		sFilename = sFilename + Utils::IntToString(GetCurrentProcessId());
		sFilename = sFilename + "_";
	}

	sFilename = sFilename + DebugLog::s_sFilename;

	// Open file
	
	pFile = fopen(sFilename.c_str(), "a");

	if(pFile == NULL) 
	{
		string sDebug = "[ERROR] Cannot open debug file: ";
		sDebug = sDebug + sFilename;

		DebugLog::DebugError(sDebug.c_str());
		return;
	}

	// Write data

	nWritten = fwrite(p_pc_Data , sizeof(char), p_nLength, pFile);

	if(nWritten != p_nLength)
	{
		DebugLog::DebugError("[ERROR] Cannot write to debug file!");
		fclose(pFile);
		return;
	}

	// Write \r\n

	nWritten = fwrite("\r\n" , sizeof(char), 2, pFile);

	if(nWritten != 2)
	{
		DebugLog::DebugError("[ERROR] Cannot write \\r\\n to debug file!");
	}

	fclose(pFile);
}

// Log critical errors: Debug string, only for debug

void DebugLog::DebugError(string p_sString)
{
	OutputDebugString(p_sString.c_str());
}

