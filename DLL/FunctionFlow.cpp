

#include "stdafx.h"
#include "FunctionFlow.h"

// Global variables

vector<FUNCTION_FLOW*> FunctionFlow::vFlags;
CRITICAL_SECTION     FunctionFlow::gCriticalSection;
bool                 FunctionFlow::gInitialized = 0;

// Initialize critical section

void FunctionFlow::Init()
{
	if(gInitialized == 0)
	{
		InitializeCriticalSection(&gCriticalSection);
		gInitialized = 1;
	}
}

// Function to check if a flag is set: auto set if it is not set

BOOL FunctionFlow::CheckFlag()
{
	DWORD tid = GetCurrentThreadId();

	EnterCriticalSection(&gCriticalSection);

	// Search tid in vector

	for (unsigned i = 0; i < vFlags.size(); ++i)
    {
        if(vFlags[i]->dwThreadId == tid) 
		{
			if(vFlags[i]->bFlag == TRUE)
			{
				// If flag is already set, return TRUE

				LeaveCriticalSection(&gCriticalSection);
				return TRUE;
			}
			else 
			{
				// If flags is NOT set, we set it and return FALSE, do actions

				vFlags[i]->bFlag = TRUE;

				LeaveCriticalSection(&gCriticalSection);
				return FALSE;
			}
		}
    }

	// Create flag element

	FUNCTION_FLOW *oFlag = new FUNCTION_FLOW;
	oFlag->bFlag = TRUE;
	oFlag->dwThreadId = tid;

	// Add to vector

	vFlags.push_back(oFlag);

	LeaveCriticalSection(&gCriticalSection);

	// Do actions

	return FALSE;
}

// Function to remove a flag

void FunctionFlow::UnCheckFlag()
{
	DWORD tid = GetCurrentThreadId();
	
	EnterCriticalSection(&gCriticalSection);

	// Search tid in vector

	for (unsigned i = 0; i < vFlags.size(); ++i)
    {
        if(vFlags[i]->dwThreadId == tid) 
		{
			// delete vFlags[i];
			// vFlags.erase(vFlags.begin() + i);

			vFlags[i]->bFlag = FALSE;
			break;
		}
    }

	LeaveCriticalSection(&gCriticalSection);
}

