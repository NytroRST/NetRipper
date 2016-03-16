
#ifndef _HOOKER_H_
#define _HOOKER_H_

#include <Windows.h>
#include <string>
#include "Process.h"
#include "DebugLog.h"

using namespace std;

// Number of bytes to replace

#define REPLACE_BYTES				5
#define HOT_PATCH_SIG_LENGTH		10

// Structure to save all hook info

struct HookStruct
{
	void *m_CallbackAddress;
	void *m_OriginalAddress;
	unsigned char m_OriginalBytes[REPLACE_BYTES];
	unsigned char m_JmpBytes[REPLACE_BYTES];
	bool m_bIsHotPatch;
};

// Hooker class :D

class Hooker
{
	// Vector where we save all hooks

	static vector<HookStruct *> s_vHooks;

	// Save hook structures to our vector
	
	static void AddHookStruct(HookStruct *p_poHookStruct);
	static void RemoveHookStruct(HookStruct *p_poHookStruct);

	// Get HookStruct* from vector by Original Address 

	static HookStruct *GetHookStructByOriginalAddress(void *p_pvOriginalAddress);

public:

	// Public functions to set/restore a hook

	static bool AddHook(string p_sDllName, string p_sAPIName, void *p_pvCallbackAddress);
	static bool AddHook(void *p_pfFunctionAddress, void *p_pvCallbackAddress);
	static void RestoreHook(void *p_pvCallbackAddress);
	static void RemoveHooks();
};

// Hook kewl function

extern "C" void Hook();

#endif
