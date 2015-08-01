
#include "stdafx.h"
#include "Utils.h"

// Function to convert a string to lower

string Utils::ToLower(string p_sString)
{
	string result = "";

	for(size_t i = 0; i < p_sString.length(); i++)
	{
		if(p_sString[i] >= 65 && p_sString[i] <= 90) result += (char)(p_sString[i] + 32);
		else result += p_sString[i];
	}
	
	return result;
}

// Function to convert non-printable chars into " "

string Utils::ToPrintable(const char *p_pcString, size_t p_nLength)
{
	string result = "";

	for(size_t i = 0; i < p_nLength; i++)
	{
		if(p_pcString[i] != 0) result += p_pcString[i];
		else result += " ";
	}

	return result;
}

// Get filename: PID_processname_filename

string Utils::GetFilename(string p_sFilename)
{
	char pcBuffer[MAX_TEMP_PATH] = {0};
	string sResult = "";

	// Get module name

	sResult = Utils::IntToString(GetCurrentProcessId());
	sResult += "_";

	if(GetModuleFileName(NULL, pcBuffer, MAX_TEMP_PATH) == 0)
	{
		DebugLog::DebugError("[ERROR] Cannot get current module name!");
		sResult += "NetRipper.txt";
	}
	else 
	{
		// Get filename only

		string sFullPath = pcBuffer;
		
		int i = sFullPath.find_last_of('\\');
		if (i != string::npos)
			sFullPath = sFullPath.substr(i+1); 
		
		sResult += sFullPath;
	}

	// Add filename

	sResult += "_";
	sResult += p_sFilename;

	return sResult;
}

// Write data (append) to temporary file (/Temp)

void Utils::WriteToTempFile(string p_sFilename, const unsigned char *p_pcBuffer, size_t p_nLength)
{
	FILE *pFile = NULL;
	string sPath = "";
	size_t nWritten = 0;

	sPath = DynConfig::GetDataPath();
	sPath = sPath + Utils::GetFilename(p_sFilename);

	// Open file
	
	pFile = fopen(sPath.c_str(), "a");

	if(pFile == NULL) 
	{
		string sDebug = "Cannot open data file: ";
		sDebug = sDebug + sPath;

		DebugLog::DebugError(sDebug.c_str());
		return;
	}

	// Write data

	nWritten = fwrite(p_pcBuffer , sizeof(char), p_nLength, pFile);

	if(nWritten != p_nLength)
	{
		string sDebug = "Cannot write to data file: ";
		sDebug = sDebug + sPath;

		DebugLog::DebugError(sDebug.c_str());
	}

	fclose(pFile);
}

// Converts an integer to string

string Utils::IntToString(unsigned int p_nNumer)
{
	string sResult = "";
	ostringstream ss;

    ss << p_nNumer;
	sResult = ss.str();

	return sResult;
}

// Converts a string to integer

unsigned int Utils::StringToInt(string p_sNumer)
{
	unsigned int ret = 0;

	ret = stoi(p_sNumer);

	return ret;
}

// Converts an integer to hex string

string Utils::IntToHex(unsigned int p_nNumer)
{
	string sResult = "";
	ostringstream ss;

    ss << std::hex << p_nNumer;
	sResult = ss.str();

	return sResult;
}

// Get string between two separators

string Utils::GetStringBetween(string p_sString, string p_sStart, string p_sStop)
{
    int start = p_sString.find(p_sStart);
    int end = p_sString.find(p_sStop, start);
    string substring = "";

	// Get strings

    if (start != std::string::npos && end != std::string::npos)
    {
		substring = p_sString.substr(start + p_sStart.length(), end - start - p_sStop.length() + 1);
    }
    else
    {
		DebugLog::LogString("[ERROR] Cannot get string between separators in: ", p_sString);
		return "";
    }

    return substring;
}

// Split a string in multiple strings

vector<string> Utils::SplitString(string p_sString, string p_sDelimiter)
{
	vector<string> sVector;

    size_t lastPos = 0;
    size_t pos = p_sString.find(p_sDelimiter, lastPos);

    while (string::npos != pos) 
	{    
        sVector.push_back(p_sString.substr(lastPos, pos - lastPos));
        lastPos = pos + p_sDelimiter.size();
        pos = p_sString.find(p_sDelimiter, lastPos);
    }

    sVector.push_back(p_sString.substr(lastPos, p_sString.size() - lastPos));
    return sVector;
}
