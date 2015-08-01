
#include "stdafx.h"
#include "PluginSystem.h"

// All plugins

vector<Plugin*> PluginSystem::s_vPlugins;

// Function to add a new plugin

void PluginSystem::InstallPlugin(Plugin *p_oPlugin)
{
	s_vPlugins.push_back(p_oPlugin);
}

// Function to remove a plugin

void PluginSystem::UninstallPlugin(Plugin *p_oPlugin)
{
	// Search hwnd in vector

	for (unsigned i = 0; i < s_vPlugins.size(); i++)
    {
        if(s_vPlugins[i] == p_oPlugin) 
		{
			delete s_vPlugins[i];
			s_vPlugins.erase(s_vPlugins.begin() + i);
		}
    }
}

// Function that returns process read data through all plugins

PLUGIN_DATA PluginSystem::ProcessReadData(unsigned char *p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;
	unsigned char *p = NULL;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if(p_pcData == NULL || p_nSize == 0) return ret;
	
	// Iterate through plugins

	for (size_t i = 0; i < s_vPlugins.size(); i++)
    {
		p = ret.data;
		ret = s_vPlugins[i]->ProcessReadData(ret.data, ret.size);
		if(i != 0 && ret.data != p) delete[] p;
    }

	return ret;
}

// Function that returns process write data through all plugins

PLUGIN_DATA PluginSystem::ProcessWriteData(unsigned char *p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;
	unsigned char *p = NULL;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if(p_pcData == NULL || p_nSize == 0) return ret;

	// Iterate through plugins

	for (size_t i = 0; i < s_vPlugins.size(); i++)
    {
		p = ret.data;
		ret = s_vPlugins[i]->ProcessWriteData(ret.data, ret.size);
		if(i != 0 && ret.data != p) delete[] p;
    }

	return ret;
}

// Will process read data and save it to a file

void PluginSystem::ProcessAndSaveRead(string p_sFilename, unsigned char *p_pcData, unsigned int p_nSize)
{
	if(p_pcData == NULL || p_nSize == 0) return;
	
	PLUGIN_DATA ret = PluginSystem::ProcessReadData(p_pcData, p_nSize);

	if(ret.size > 0) Utils::WriteToTempFile(p_sFilename, ret.data, ret.size);
	if(ret.data != p_pcData) delete[] ret.data;
}

// Will process write data and write it to a file

void PluginSystem::ProcessAndSaveWrite(string p_sFilename, unsigned char *p_pcData, unsigned int p_nSize)
{
	if(p_pcData == NULL || p_nSize == 0) return;
	
	PLUGIN_DATA ret = PluginSystem::ProcessWriteData(p_pcData, p_nSize);

	if(ret.size > 0) Utils::WriteToTempFile(p_sFilename, ret.data, ret.size);
	if(ret.data != p_pcData) delete[] ret.data;
}
