
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
		
		size_t i = sFullPath.find_last_of('\\');
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

	if (p_pcBuffer == NULL || p_nLength == 0)
	{
		DebugLog::Log("WARNING: Cannot write NULL data");
		return;
	}

	sPath = DynConfig::GetDataPath();
	sPath = sPath + Utils::GetFilename(p_sFilename);

	// Open file
	
	pFile = fopen(sPath.c_str(), "ab");

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
    size_t start = p_sString.find(p_sStart);
	size_t end = p_sString.find(p_sStop, start);
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

// Check if a process is 32 bit or 64 bit

bool Utils::Is32BitProcess()
{
	if (sizeof(void*) == 4) return true;
	else return false;
}

// Get IP and port information

IPInfo Utils::GetIPInfo(unsigned int p_nSocket)
{
	IPInfo data;
	sockaddr_in sock_client, sock_server;
	int len_client = sizeof(sock_client);
	int len_server = sizeof(sock_server);

	// Get socket data

	memset(&sock_client, 0, sizeof(sock_client));
	memset(&sock_server, 0, sizeof(sock_server));

	getsockname((SOCKET)p_nSocket, (struct sockaddr *)&sock_client, &len_client);
	getpeername((SOCKET)p_nSocket, (struct sockaddr *)&sock_server, &len_server);

	// Save data

	data.nSrcIP = (uint32_t)sock_client.sin_addr.S_un.S_addr;
	data.nDstIP = (uint32_t)sock_server.sin_addr.S_un.S_addr;
	data.nSrcPort = (uint16_t)ntohs(sock_client.sin_port);
	data.nDstPort = (uint16_t)ntohs(sock_server.sin_port);

	return data;
}
