
#include "stdafx.h"
#include "Plugin.h"

// Initialize pointers

Plugin::Plugin()
{
	ReadCallback = NULL;
	WriteCallback = NULL;
}

// Set config data

void Plugin::SetConfig(string p_sConfig)
{ 
	m_sConfig = p_sConfig;
}

// Called by PluginSystem to process read data

PLUGIN_DATA Plugin::ProcessReadData(unsigned char *p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if(this->ReadCallback != NULL) ret = this->ReadCallback(ret.data, ret.size, this->m_sConfig);

	return ret;
}

// Called by PluginSystem to process write data

PLUGIN_DATA Plugin::ProcessWriteData(unsigned char *p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if(this->WriteCallback != NULL) ret = this->WriteCallback(ret.data, ret.size, this->m_sConfig);

	return ret;
}


// Plugin that extracts only plain text

PLUGIN_DATA Plugin_PlainText(unsigned char *p_pcData, unsigned int p_nSize, string p_sConfigData)
{
	PLUGIN_DATA ret;
	unsigned int new_size = 0;

	ret.data = new unsigned char[p_nSize];

	// Get only printable text

	for(size_t i = 0; i < p_nSize; i++)
	{
		if(p_pcData[i] >= 32 && p_pcData[i] <= 126) ret.data[new_size++] = p_pcData[i];
		if(p_pcData[i] == 0xA || p_pcData[i] == 0xD) ret.data[new_size++] = p_pcData[i];
	}

	ret.size = new_size;

	return ret;
}

// Plugin to limit data

PLUGIN_DATA Plugin_DataLimit(unsigned char *p_pcData, unsigned int p_nSize, string p_sConfigData)
{
	PLUGIN_DATA ret;
	unsigned int max_data = Utils::StringToInt(p_sConfigData);

	if(max_data == 0 || max_data > p_nSize) 
		max_data = p_nSize;

	ret.data = new unsigned char[max_data];
	ret.size = max_data;

	// Copy first max_data data

	memcpy(ret.data, p_pcData, max_data);
	
	return ret;
}

// Plugin to find specific strings

PLUGIN_DATA Plugin_StringFinder(unsigned char *p_pcData, unsigned int p_nSize, string p_sConfigData)
{
	PLUGIN_DATA ret;
	
	ret.data = p_pcData;
	ret.size = p_nSize;

	// Search strings, data will be saved in other file

	vector<string> searchStrings = Utils::SplitString(p_sConfigData, ",");
	for(size_t x = 0; x < searchStrings.size(); x++) searchStrings[x] = Utils::ToLower(searchStrings[x]);
	vector<string> lineStrings = Utils::SplitString((char *)p_pcData, "\n");

	// Find strings

	for(size_t y = 0; y < lineStrings.size(); y++)
	{
		bool bFound = false;
		
		for(size_t i = 0; i < lineStrings[y].length(); i++)
		{
			string Tmp = Utils::ToLower((char *)(lineStrings[y].c_str() + i));

			for(size_t j = 0; j < searchStrings.size(); j++)
			{
				if(Tmp.substr(0, searchStrings[j].length()).compare(searchStrings[j]) == 0) 
				{
					Utils::WriteToTempFile("StringFinder.txt", (unsigned char *)lineStrings[y].c_str(), lineStrings[y].length());
					Utils::WriteToTempFile("StringFinder.txt", (unsigned char *)"\r\n\r\n", 4);
					bFound = true;
					break;
				}
			}

			// Write only once

			if(bFound == true) break;
		}
	}
	
	return ret;
}
