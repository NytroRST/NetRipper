/*
	Name:   NetRipper Project
	Author: Ionut Popescu <ionut.popescu@outlook.com>
*/

#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>

using namespace std;

// Temporary configured DLL

#define TEMP_DLL_FILE "/usr/share/metasploit-framework/modules/post/windows/gather/netripper/NewDLL.dll"

// Prototypes

unsigned int GetFileSize(string p_sFilename);
string GenerateData(string p_sArgs);
bool ReplaceData(string p_sDLL, string p_sData);

// Print help

void PrintHelp()
{
	cout << endl;

	cout << "Generate DLL:" << endl << endl;
	cout << "  -h,  --help          Print this help message" << endl;
	cout << "  -w,  --write         Full path for the DLL to write the configuration data" << endl;
	cout << "  -l,  --location      Full path where to save data files (default TEMP)" << endl << endl;

	cout << "Plugins:" << endl << endl;
	cout << "  -p,  --plaintext     Capture only plain-text data. E.g. true" << endl;
	cout << "  -d,  --datalimit     Limit capture size per request. E.g. 4096" << endl;
	cout << "  -s,  --stringfinder  Find specific strings. E.g. user,pass,config" << endl << endl;

	cout << "Example: ./netripper -w DLL.dll -l TEMP -p true -d 4096 -s user,pass" << endl << endl;
}

// Main

int main(int argc, char* argv[])
{
	// Arguments

	if(argc == 1)
	{
		PrintHelp();
		return 0;
	}

	// Each value

	string sDLL      = "";
	string sLocation = "TEMP";
	string sPlain    = "true";
	string sLimit    = "4096";
	string sFinder   = "user,login,pass,database,config";

	// All options

	for(int i = 0; i < argc; i++)
	{
		string sArg = argv[i];

		// Help

		if(sArg.compare("-h") == 0 || sArg.compare("--help") == 0)
		{
			PrintHelp();
			return 0;
		}

		// Write DLL

		if(sArg.compare("-w") == 0 || sArg.compare("--write") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "Invalid option specified: " << sArg << endl;
				return 1;
			}

			sDLL = (string)argv[i + 1];
		}

		// Location

		if(sArg.compare("-l") == 0 || sArg.compare("--location") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "Invalid option specified: " << sArg << endl;
				return 1;
			}

			sLocation = (string)argv[i + 1];
		}

		// Plain

		if(sArg.compare("-p") == 0 || sArg.compare("--plaintext") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "Invalid option specified: " << sArg << endl;
				return 1;
			}

			sPlain = (string)argv[i + 1];
		}

		// Limit

		if(sArg.compare("-d") == 0 || sArg.compare("--datalimit") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "Invalid option specified: " << sArg << endl;
				return 1;
			}

			sLimit = (string)argv[i + 1];
		}

		// Finder

		if(sArg.compare("-s") == 0 || sArg.compare("--stringfinder") == 0)
		{
			if(argv[i + 1] == NULL || argv[i + 1][0] == '-') 
			{
				cout << endl << "Invalid option specified: " << sArg << endl;
				return 1;
			}

			sFinder = (string)argv[i + 1];
		}
	}

	// Create static data

	string sFinalData = "plaintext=" + sPlain + ";datalimit=" + sLimit + ";stringfinder=" + sFinder + ";"
		+ "data_path=" + sLocation + ";";

	// Write data to new DLL

	if(ReplaceData(sDLL, GenerateData(sFinalData)) == true)
		cout << endl << "DLL succesfully created: " << TEMP_DLL_FILE << endl;
	else 
		cout << endl << "Cannot create DLL " << TEMP_DLL_FILE << endl;

	return 0;
}

// Generate XML data
// E.g. plaintext=true;datalimit=4096;stringfinder=user,pass;data_path=TEMP;

string GenerateData(string p_sArgs)
{
	string sResult = "<NetRipper>";
	string option_name  = "";
	string option_value = "";

	for(size_t i = 0; i < p_sArgs.length(); )
	{
		if(p_sArgs[i] == '=')
		{
			i++;

			// Get values

			while(p_sArgs[i] != ';')
			{
				option_value += p_sArgs[i];
				i++;
			}

			// Do things with options

			sResult += "<" + option_name + ">";

			sResult += option_value;

			for(size_t j = 0; j < 256 - option_value.length(); j++)
				sResult += '?';

			sResult += "</" + option_name + ">";

			// Reset

			option_name = "";
			option_value = "";
			i++;
		}

		option_name += p_sArgs[i];
		i++;
	}

	sResult += "</NetRipper>";
	return sResult;
}

// Replace configuration data into DLL

bool ReplaceData(string p_sDLL, string p_sData)
{
	FILE *hFile;
	FILE *pFile;
	size_t nWritten = 0;
	unsigned char *lpBuffer = NULL;
	unsigned int dwLength = 0, dwBytesRead = 0;
	
	// Open DLL for read

	hFile = fopen( p_sDLL.c_str(), "rb" );

	if( hFile == NULL )
	{
		cout << "Cannot read DLL file: " << p_sDLL << endl;
		return false;
	}

	// Get DLL size

	dwLength = GetFileSize( p_sDLL );
	
	if( dwLength == 0 )
	{
		cout << "Failed to get the DLL file size" << endl;
		return false;
	}

	// Allocate space for DLL

	lpBuffer = (unsigned char *)malloc( dwLength );
		
	if( !lpBuffer )
	{
		cout << "Failed to allocate space!" << endl;
		return false;
	}

	// Read DLL
	
	dwBytesRead = fread( lpBuffer, 1, dwLength, hFile );

	if( dwBytesRead != dwLength )
	{
		cout << "Failed to read file!" << endl;
		return false;
	}

	// Parse data buffer and find XML settings

	unsigned char pcSearchString[] = "<NetRipper>";
	unsigned int dwSearchSize = 11;
	bool bFound = true;

	for(unsigned int i = 0; i < dwBytesRead - dwSearchSize; i++)
	{
		bFound = true;

		for(unsigned int j = i; j < i + dwSearchSize; j++)
		{
			if(lpBuffer[j] != pcSearchString[j - i]) bFound = false;
		}

		// Found data, write data

		if(bFound) 
		{
			// Open file
			
			pFile = fopen(TEMP_DLL_FILE, "wb");

			if(pFile == NULL) 
			{
				cout << "Cannot open temporary DLL file: " << TEMP_DLL_FILE << endl;
				return false;;
			}

			// Write first chunk of data

			nWritten = fwrite(lpBuffer , sizeof(char), i, pFile);

			if(nWritten != i)
			{
				cout << "Cannot write first chunk to temporary DLL file: " << TEMP_DLL_FILE << endl;
				return false;
			}

			// Write configured data p_sData

			nWritten = fwrite(p_sData.c_str(), sizeof(char), p_sData.length(), pFile);

			if(nWritten != p_sData.length())
			{
				cout << "Cannot write configured data to temporary DLL file: " << TEMP_DLL_FILE << endl;
				return false;
			}

			// Write the rest of the DLL

			nWritten = fwrite(lpBuffer + i + p_sData.length(), sizeof(char), dwBytesRead - i - p_sData.length(), pFile);

			if(nWritten != dwBytesRead - i - p_sData.length())
			{
				cout << "Cannot write full data to temporary DLL file: " << TEMP_DLL_FILE << endl;
				return false;
			}
			
			fclose(pFile);
		}
	}

	// Cleanup

	if( hFile )
		fclose( hFile );

	if( lpBuffer )
		free( lpBuffer );

	return true;
}

// Get file size

unsigned int GetFileSize(string p_sFilename)
{
  struct stat statbuf;

  if (stat(p_sFilename.c_str(), &statbuf) == -1) 
  {
	return 0;
  }

  return statbuf.st_size;
}
