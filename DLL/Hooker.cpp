
#include "stdafx.h"
#include "Hooker.h"

// Global vector

vector<HookStruct *> Hooker::s_vHooks;

// Windows hot-patching signature (nops, mov edi, edi)

unsigned char s_ucHotPatchSignature[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x8B, 0xFF, 0x55, 0x8B, 0xEC};
unsigned char s_ucJumpBack[]  = {0xEB, 0xF9};
unsigned char s_ucMovEdiEdi[] = {0x8B, 0xFF};

// Our "naked" hook function

extern "C" __declspec(naked) void Hook()
{	
	__asm 
	{
		// Get hooked function address

		mov EAX, [ESP]                               // Get EIP_CALLING
		sub EAX, 5                                   // Sizeof call

		// Backup ECX to support __thiscall

		push ECX

		// Get and parse HookStruct

		push EAX                                     // Function parameter
		call Hooker::GetHookStructByOriginalAddress  // Call function
		add ESP, 4                                   // Clean stack (cdecl)

		push EAX                                     // Backup register

		// Get data from HookStruct

		mov EDX, [EAX + 4]                           // EDX == m_OriginalAddress                           
		add EAX, 8                                   // EAX == m_OriginalBytes

		// Check for hot-patching

		add EAX, 10									 // Pointer to m_bIsHotPatch
		add EDX, 5									 // Location for placing mov edi, edi
		cmp BYTE PTR [EAX], 1						 // Check value of m_bIsHotPatch
		jne NoHotPatch								 // Hot patching flag is not set

		mov BYTE PTR [EDX], 0x8B					 // Add first byte of mov edi, edi
		add EDX, 1									 // Go to next byte
		mov BYTE PTR [EDX], 0xFF					 // Add second byte of mov edi, edi
		sub EDX, 1									 // Go back

		NoHotPatch:
		sub EAX, 10									 // Restore original bytes address
		sub EDX, 5									 // Restore original address

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

		// Restore ECX for __thiscall

		pop ECX

		// Call callback function

		add ESP, 4                                   // "Remove" EIP_Calling from stack
		mov EDX, [EAX]                               // Get callback pointer
		jmp EDX                                      // Jump to callback function 
	}
}

// Function restores the hook on a function already hooked!

void Hooker::RestoreHook(void *p_pvCallbackAddress)
{
	// Search hwnd in vector

	for (unsigned i = 0; i < s_vHooks.size(); ++i)
    {
		if(s_vHooks[i]->m_CallbackAddress == p_pvCallbackAddress) 
		{
			// Check for hot paching

			if(s_vHooks[i]->m_bIsHotPatch) 
			{
				memcpy(s_vHooks[i]->m_OriginalAddress, s_vHooks[i]->m_JmpBytes, REPLACE_BYTES);
				memcpy((void *)((DWORD)s_vHooks[i]->m_OriginalAddress + 5), s_ucJumpBack, 2);
				FlushInstructionCache(GetCurrentProcess(), s_vHooks[i]->m_OriginalAddress, REPLACE_BYTES + 2);
			}
			else
			{
				memcpy(s_vHooks[i]->m_OriginalAddress, s_vHooks[i]->m_JmpBytes, REPLACE_BYTES);
				FlushInstructionCache(GetCurrentProcess(), s_vHooks[i]->m_OriginalAddress, REPLACE_BYTES);
			}
		}
    }
}

// Function removes the hooks on functions already hooked!

void Hooker::RemoveHooks()
{
	// Remove all hooks

	for (unsigned i = 0; i < s_vHooks.size(); ++i)
    {
		if(s_vHooks[i]->m_bIsHotPatch) 
		{
			memcpy(s_vHooks[i]->m_OriginalAddress, s_vHooks[i]->m_OriginalBytes, REPLACE_BYTES);
			memcpy((void *)((DWORD)s_vHooks[i]->m_OriginalAddress + 5), s_ucMovEdiEdi, 2);		
			FlushInstructionCache(GetCurrentProcess(), s_vHooks[i]->m_OriginalAddress, REPLACE_BYTES + 2);
		}
		else
		{
			memcpy(s_vHooks[i]->m_OriginalAddress, s_vHooks[i]->m_OriginalBytes, REPLACE_BYTES);
			FlushInstructionCache(GetCurrentProcess(), s_vHooks[i]->m_OriginalAddress, REPLACE_BYTES);
		}

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
		return false;
	}

	// Check for Windows Hot-Patching

	if(memcmp((void *)((DWORD)p_pfFunctionAddress - 5), (void *)(s_ucHotPatchSignature), HOT_PATCH_SIG_LENGTH) == 0)
	{
		// Original function pointer
		
		pHook->m_bIsHotPatch = true;
		pHook->m_OriginalAddress = (void *)((DWORD)p_pfFunctionAddress - 5);

		// Create CALL
				
		jump = 0xFFFFFFFF - ((DWORD)pHook->m_OriginalAddress + 4 - (DWORD)Hook);

		// Place a CALL (not a JMP)
					
		pHook->m_JmpBytes[0] = (char)0xE8;
		memcpy(&pHook->m_JmpBytes[1], &jump, 4);
	}
	else
	{
		// Original function pointer
		
		pHook->m_bIsHotPatch = false;
		pHook->m_OriginalAddress = (void *)p_pfFunctionAddress;
					
		// Create CALL
				
		jump = 0xFFFFFFFF - ((DWORD)pHook->m_OriginalAddress + 4 - (DWORD)Hook);

		// Place a CALL (not a JMP)
					
		pHook->m_JmpBytes[0] = (char)0xE8;
		memcpy(&pHook->m_JmpBytes[1], &jump, 4);		
	}

	// Set page permissions

	VirtualProtect(pHook->m_OriginalAddress, 4096, PAGE_EXECUTE_READWRITE, &oldP);

	// Copy original bytes

	memcpy(pHook->m_OriginalBytes, pHook->m_OriginalAddress, REPLACE_BYTES);
	if(pHook->m_bIsHotPatch) memcpy((void *)((DWORD)pHook->m_OriginalAddress + 5), s_ucJumpBack, 2);

	// Set hook

	memcpy(pHook->m_OriginalAddress, pHook->m_JmpBytes, REPLACE_BYTES);
	FlushInstructionCache(GetCurrentProcess(), pHook->m_OriginalAddress, REPLACE_BYTES + 2);

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

	DebugLog::LogIntHex("[ERROR] Cannot get hook by original address: ", (DWORD)p_pvOriginalAddress);

	return NULL;
}
