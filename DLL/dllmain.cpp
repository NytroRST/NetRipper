
#include "stdafx.h"
#include "InjectedDLL.h"

// DLL Entrypoint

BOOL APIENTRY DllMain(HINSTANCE p_hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	    // Add hooks

		case DLL_PROCESS_ATTACH:
			Inject();
			break;
	    case DLL_THREAD_ATTACH:
			break;
	    case DLL_THREAD_DETACH:
			break;

		// Remove hooks

	    case DLL_PROCESS_DETACH:
			Unhook();
			break;
	}

	return TRUE;
}

