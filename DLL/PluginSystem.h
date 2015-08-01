
#ifndef _PLUGINSYSTEM_H_
#define _PLUGINSYSTEM_H_

#include <vector>

#include "DynConfig.h"
#include "Utils.h"
#include "Plugin.h"

using namespace std;

// Plugin system class

class PluginSystem
{
private:
	static vector<Plugin*> s_vPlugins;

public:
	static void InstallPlugin(Plugin *p_oPlugin);
	static void UninstallPlugin(Plugin *p_oPlugin);
	static PLUGIN_DATA ProcessReadData(unsigned char *p_pcData, unsigned int p_nSize);
	static PLUGIN_DATA ProcessWriteData(unsigned char *p_pcData, unsigned int p_nSize);
	static void ProcessAndSaveRead(string p_sFilename, unsigned char *p_pcData, unsigned int p_nSize);
	static void ProcessAndSaveWrite(string p_sFilename, unsigned char *p_pcData, unsigned int p_nSize);
};

#endif
