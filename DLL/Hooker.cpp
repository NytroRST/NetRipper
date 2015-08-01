
#include "stdafx.h"
#include "Hooker.h"

// Our "naked" hook function

extern "C" __declspec(naked) void Hook()
{	
	__asm 
	{
		// Get hooked function address

		mov EAX, [ESP]                               // Get EIP_CALLING
		sub EAX, 5                                   // Sizeof call

		// Get and parse HookStruct

		push EAX                                     // Function parameter
		call Hooker::GetHookStructByOriginalAddress  // Call function
		add ESP, 4                                   // Clean stack (cdecl)

		push EAX                                     // Backup register

		// Get data from HookStruct

		mov EDX, [EAX + 4]                           // EDX == m_OriginalAddress                           
		add EAX, 8                                   // EAX == m_OriginalBytes

		// Restore bytes

		push REPLACE_BYTES                           // REPLACE_BYTES
		push EAX                                     // m_OriginalBytes
		push EDX                                     // m_OriginalAddress
		call DWORD PTR memcpy                        // __cdecl memcpy(m_OriginalAddress, m_OriginalBytes, REPLACE_BYTES)
		add  ESP, 0xC                                // Clean stack

		pop EAX                                      // Restore register
		push EAX                                     // Backup register

		// Flush instruction cache
		
		push REPLACE_BYTES                           // REPLACE_BYTES
		mov EDX, [EAX + 4]                           // EDX == m_OriginalAddress
		push EDX                                     // m_OriginalAddress
		push 0xFFFFFFFF                              // hProcess (process handle) - current process (-1)
		call DWORD PTR [FlushInstructionCache]       // FlushInstructionCache(-1, m_OriginalAddress, REPLACE_BYTES)

		pop EAX                                      // Restore register

		// Call callback function

		add ESP, 4                                   // "Remove" EIP_Calling from stack
		mov EDX, [EAX]                               // Get callback pointer
		jmp EDX                                      // Jump to callback function 
	}
}

// Global vector

vector<HookStruct *> Hooker::s_vHooks;

// Function restores the hook on a function already hooked!

void Hooker::RestoreHook(void *p_pvCallbackAddress)
{
	// Search hwnd in vector

	for (unsigned i = 0; i < s_vHooks.size(); ++i)
    {
		if(s_vHooks[i]->m_CallbackAddress == p_pvCallbackAddress) 
		{
			memcpy(s_vHooks[i]->m_OriginalAddress, s_vHooks[i]->m_JmpBytes, REPLACE_BYTES);
			FlushInstructionCache(GetCurrentProcess(), s_vHooks[i]->m_OriginalAddress, REPLACE_BYTES);
		}
    }
}

// Function removes the hooks on functions already hooked!

void Hooker::RemoveHooks()
{
	// Remove all hooks

	for (unsigned i = 0; i < s_vHooks.size(); ++i)
    {
		memcpy(s_vHooks[i]->m_OriginalAddress, s_vHooks[i]->m_OriginalBytes, REPLACE_BYTES);
		FlushInstructionCache(GetCurrentProcess(), s_vHooks[i]->m_OriginalAddress, REPLACE_BYTES);

		delete s_vHooks[i];
    }

	// Remove pointers

	s_vHooks.clear();
}

// Add hook to specific address

bool Hooker::AddHook(void *p_pfFunctionAddress, void *p_pvCallbackAddress)
{
	DWORD jump;
	DWORD oldP;

	HookStruct *pHook = new HookStruct;
	pHook->m_CallbackAddress = p_pvCallbackAddress;

	// Check pointers

	if(p_pfFunctionAddress == NULL || p_pvCallbackAddress == NULL)
	{
		DebugLog::Log("[ERROR] Invalid pointer to add HOOK!");
		MessageBox(0, "Invalid pointer!", "NetRipper", 0);
	}

	// Original function pointer
					
	pHook->m_OriginalAddress = (void *)p_pfFunctionAddress;
					
	// Create CALL
				
	jump = 0xFFFFFFFF - ((DWORD)pHook->m_OriginalAddress + 4 - (DWORD)Hook);

	// Place a CALL (not a JMP)
					
	pHook->m_JmpBytes[0] = (char)0xE8;
	memcpy(&pHook->m_JmpBytes[1], &jump, 4);
					
	// Set page permissions

	VirtualProtect(pHook->m_OriginalAddress, 4096, PAGE_EXECUTE_READWRITE, &oldP);

	// Copy original bytes

	memcpy(pHook->m_OriginalBytes, pHook->m_OriginalAddress, REPLACE_BYTES);

	// Set hook

	memcpy(pHook->m_OriginalAddress, pHook->m_JmpBytes, REPLACE_BYTES);
	FlushInstructionCache(GetCurrentProcess(), pHook->m_OriginalAddress, REPLACE_BYTES);

	// Add struct to vector

	Hooker::RemoveHookStruct(pHook);
	Hooker::AddHookStruct(pHook);

	return true;
}

// Function to add a new hook struct

void Hooker::AddHookStruct(HookStruct *p_poHookStruct)
{
	s_vHooks.push_back(p_poHookStruct);
}

// Function to remove a hook struct

void Hooker::RemoveHookStruct(HookStruct *p_poHookStruct)
{
	// Search hwnd in vector

	for (unsigned i = 0; i < s_vHooks.size(); ++i)
    {
        if(s_vHooks[i] == p_poHookStruct) 
		{
			delete s_vHooks[i];
			s_vHooks.erase(s_vHooks.begin() + i);
		}
    }
}

// Function that returns a pointer to HookStruct by OriginalAddress

HookStruct *Hooker::GetHookStructByOriginalAddress(void *p_pvOriginalAddress)
{
	// Search hwnd in vector

	for (unsigned i = 0; i < s_vHooks.size(); ++i)
    {
		if(s_vHooks[i]->m_OriginalAddress == p_pvOriginalAddress) 
		{
			return s_vHooks[i]; 
		}
    }

	DebugLog::LogString("[ERROR] Cannot get hook by original address: ", Utils::IntToString((unsigned int)p_pvOriginalAddress));

	return NULL;
}
