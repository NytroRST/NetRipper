
#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include <string>
#include "DynConfig.h"
#include "Utils.h"

using namespace std;

// Structure used to return modified data

struct PLUGIN_DATA
{
	unsigned char *data;
	unsigned int   size;
};

class Plugin;

// Callback

typedef PLUGIN_DATA (*PluginCallback_Typedef)(unsigned char *, unsigned int, string);

// Plugin system class

class Plugin
{
private:
	string m_sConfig;

public:
	Plugin();
	void SetConfig(string p_sConfig);

	// Called functions

	PLUGIN_DATA ProcessReadData(unsigned char *p_pcData, unsigned int p_nSize);
	PLUGIN_DATA ProcessWriteData(unsigned char *p_pcData, unsigned int p_nSize);

	// Read & Write callback

	PluginCallback_Typedef ReadCallback;
	PluginCallback_Typedef WriteCallback;
};

// Plugins

PLUGIN_DATA Plugin_PlainText(unsigned char *p_pcData, unsigned int p_nSize, string p_sConfigData);
PLUGIN_DATA Plugin_DataLimit(unsigned char *p_pcData, unsigned int p_nSize, string p_sConfigData);
PLUGIN_DATA Plugin_StringFinder(unsigned char *p_pcData, unsigned int p_nSize, string p_sConfigData);

#endif
