
#ifndef _NONEXPORTEDHOOKS_H_
#define _NONEXPORTEDHOOKS_H_

#include "Process.h"
#include "HookedFunctions.h"

// Statically linked files

void HookChrome(string p_sModule);
void HookPutty();
void HookWinSCP();
void HookSlack();

#endif
