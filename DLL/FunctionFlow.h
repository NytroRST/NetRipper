
#ifndef _FUNCTIONFLOW_H_
#define _FUNCTIONFLOW_H_

#include <Windows.h>
#include <vector>

using namespace std;

// Struct for flags

struct FUNCTION_FLOW
{
	DWORD dwThreadId;
	BOOL  bFlag;
};

class FunctionFlow
{
	// Vector of flags

	static vector<FUNCTION_FLOW*> vFlags;
	static CRITICAL_SECTION gCriticalSection;
	static bool gInitialized;

public:

	static void Init();

	// Functions 

	static BOOL CheckFlag();
	static void UnCheckFlag();
};

#endif