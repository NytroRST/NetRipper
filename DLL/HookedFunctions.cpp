
#include "stdafx.h"
#include "HookedFunctions.h"

// Variables (function pointers)

PR_Write_Typedef PR_Write_Original;
PR_Read_Typedef PR_Read_Original;
PR_GetDescType_Typedef PR_GetDescType_Original;

SSL_Write_Typedef SSL_Write_Original;
SSL_Read_Typedef SSL_Read_Original;

SSLeay_Write_Typedef SSLeay_Write_Original;
SSLeay_Read_Typedef SSLeay_Read_Original;

PR_Send_Typedef PR_Send_Original;
PR_Recv_Typedef PR_Recv_Original;

SSH_Pktsend_Typedef SSH_Pktsend_Original;
SSH_Rdpkt_Typedef SSH_Rdpkt_Original;

SslEncryptPacket_Typedef SslEncryptPacket_Original;
SslDecryptPacket_Typedef SslDecryptPacket_Original;

send_Typedef send_Original;
recv_Typedef recv_Original;

WSASend_Typedef WSASend_Original;
WSARecv_Typedef WSARecv_Original;

EncryptMessage_Typedef EncryptMessage_Original;
DecryptMessage_Typedef DecryptMessage_Original;

PuttySend_Typedef PuttySend_Original;
PuttyRecv_Typedef PuttyRecv_Original;

SecureCRT_Typedef SecureCRT_Original;

// PR_Write callback

int PR_Write_Callback(void *fd, void *buffer, DWORD amount)
{
	LONG res;

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		// Check if this is traffic

		if ((PR_GetDescType_Original(fd) == 2 || PR_GetDescType_Original(fd) == 4) && buffer != NULL)
		{
			PluginSystem::ProcessAndSaveWrite("PR_ReadWrite.pcap", (unsigned char *)buffer, amount);
		}
	}

	// Call original function

	res = PR_Write_Original(fd, buffer, amount);

	FunctionFlow::UnCheckFlag();

	return res;
}

// PR_Read callback

int PR_Read_Callback(void *fd, void *buffer, DWORD amount)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	signed int ret = PR_Read_Original(fd, buffer, amount);

	// Do things

	if (bFlag == FALSE)
	{
		if ((PR_GetDescType_Original(fd) == 2 || PR_GetDescType_Original(fd) == 4) && ret > 0)
			PluginSystem::ProcessAndSaveRead("PR_ReadWrite.pcap", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SSL_Write callback 64 bits

int SSL_Write_Callback(void *fd, void *buffer, int amount)
{
	LONG res;

	// If allowed

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		PluginSystem::ProcessAndSaveWrite("SSL_ReadWrite.pcap", (unsigned char *)buffer, amount);
	}

	// Call original function

	res = SSL_Write_Original(fd, buffer, amount);

	FunctionFlow::UnCheckFlag();

	return res;
}

// SSL_Read callback 64 bits

int SSL_Read_Callback(void *fd, void *buffer, int amount)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	int ret = SSL_Read_Original(fd, buffer, amount);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret > 0) PluginSystem::ProcessAndSaveRead("SSL_ReadWrite.pcap", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SSLeay_Write callback

int SSLeay_Write_Callback(void *fd, void *buffer, int amount)
{
	LONG res;

	// If allowed

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		PluginSystem::ProcessAndSaveWrite("SSLeay_ReadWrite.pcap", (unsigned char *)buffer, amount);
	}

	// Call original function

	res = SSLeay_Write_Original(fd, buffer, amount);

	FunctionFlow::UnCheckFlag();

	return res;
}

// SSLeay_Read callback 

int SSLeay_Read_Callback(void *fd, void *buffer, int amount)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	int ret = SSLeay_Read_Original(fd, buffer, amount);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret > 0) PluginSystem::ProcessAndSaveRead("SSLeay_ReadWrite.pcap", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// PR_Send callback

int PR_Send_Callback(void *fd, const void *buf, int amount, int flags, DWORD timeout)
{
	LONG res;

	// Do things

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (buf != NULL && amount > 0)
		{
			PluginSystem::ProcessAndSaveWrite("PR_RecvSend.pcap", (unsigned char *)buf, amount);
		}
	}

	// Call original function

	res = PR_Send_Original(fd, buf, amount, flags, timeout);

	FunctionFlow::UnCheckFlag();

	return res;
}

// PR_Recv callback

int PR_Recv_Callback(void *fd, void *buf, int amount, int flags, DWORD timeout)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	signed int ret = PR_Recv_Original(fd, buf, amount, flags, timeout);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret > 0)
			PluginSystem::ProcessAndSaveRead("PR_RecvSend.pcap", (unsigned char *)buf, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SslEncryptPacket

LONG __stdcall SslEncryptPacket_Callback(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwContentType, DWORD dwFlags)
{
	LONG res;

	// Do things

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (pbInput != NULL && cbInput > 0)
		{
			PluginSystem::ProcessAndSaveWrite("SslEncryptDecryptPacket.pcap", (unsigned char *)pbInput, cbInput);
		}
	}

	// Call original function

	res = SslEncryptPacket_Original(hSslProvider, hKey, pbInput, cbInput, pbOutput, cbOutput, pcbResult, SequenceNumber, dwContentType, dwFlags);

	FunctionFlow::UnCheckFlag();

	return res;
}

// SslDecryptPacket

LONG __stdcall SslDecryptPacket_Callback(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput,
	PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwFlags)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	LONG res = SslDecryptPacket_Original(hSslProvider, hKey, pbInput, cbInput, pbOutput, cbOutput, pcbResult, SequenceNumber, dwFlags);

	// Do things

	if (bFlag == FALSE)
	{
		if (pcbResult > 0)
			PluginSystem::ProcessAndSaveRead("SslEncryptDecryptPacket.pcap", (unsigned char *)pbOutput, *pcbResult);
	}

	FunctionFlow::UnCheckFlag();

	return res;
}

// send callback

int __stdcall send_Callback(int s, char *buf, int len, int flags)
{
	LONG res;

	// Do things

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (buf != NULL && len > 0)
		{
			PluginSystem::ProcessAndSaveWrite("recvsend.pcap", (unsigned char *)buf, len, s);
		}
	}

	// Call original function

	res = send_Original(s, buf, len, flags);

	FunctionFlow::UnCheckFlag();

	return res;
}

// recv callback

int __stdcall recv_Callback(int s, char *buf, int len, int flags)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	signed int ret = recv_Original(s, buf, len, flags);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret > 0)
			PluginSystem::ProcessAndSaveRead("recvsend.pcap", (unsigned char *)buf, ret, s);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// WSASend callback

int __stdcall WSASend_Callback(int s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int res;

	// Do things

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (lpBuffers != NULL && dwBufferCount > 0)
		{
			for (DWORD i = 0; i < dwBufferCount; i++)
			{
				PluginSystem::ProcessAndSaveWrite("recvsend.pcap", (unsigned char *)lpBuffers[i].buf, lpBuffers[i].len, s);
			}
		}
	}

	// Call original function

	res = WSASend_Original(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

	FunctionFlow::UnCheckFlag();

	return res;
}

// WSARecv callback

int __stdcall WSARecv_Callback(int s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	int ret = WSARecv_Original(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret == 0)
		{
			for (DWORD i = 0; i < dwBufferCount; i++)
			{
				PluginSystem::ProcessAndSaveRead("recvsend.pcap", (unsigned char *)lpBuffers[i].buf, lpBuffers[i].len, s);
			}
		}
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// EncryptMessage

SECURITY_STATUS __stdcall EncryptMessage_Callback(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	SECURITY_STATUS res;

	// Do things

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (pMessage->pBuffers != NULL && pMessage->cBuffers > 0)
		{
			for (DWORD i = 0; i < pMessage->cBuffers; i++)
			{
				SecBuffer buf = pMessage->pBuffers[i];

				if (buf.BufferType == SECBUFFER_DATA)
					PluginSystem::ProcessAndSaveWrite("EncryptDecryptMessage.pcap", (unsigned char *)buf.pvBuffer, buf.cbBuffer);
			}
		}
	}

	// Call original function

	res = EncryptMessage_Original(phContext, fQOP, pMessage, MessageSeqNo);

	FunctionFlow::UnCheckFlag();

	return res;
}

// DecryptMessage

SECURITY_STATUS __stdcall DecryptMessage_Callback(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	int ret = DecryptMessage_Original(phContext, pMessage, MessageSeqNo, pfQOP);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret == SEC_E_OK)
		{
			if (pMessage->pBuffers != NULL && pMessage->cBuffers > 0)
			{
				for (DWORD i = 0; i < pMessage->cBuffers; i++)
				{
					SecBuffer buf = pMessage->pBuffers[i];

					if (buf.BufferType == SECBUFFER_DATA)
						PluginSystem::ProcessAndSaveRead("EncryptDecryptMessage.pcap", (unsigned char *)buf.pvBuffer, buf.cbBuffer);
				}
			}
		}
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// PuttySend callback

void PuttySend_Callback(void *handle, char *buf, int len, int interactive)
{
	// If allowed

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (buf != NULL) PluginSystem::ProcessAndSaveWrite("PuttyRecvSend.pcap", (unsigned char *)buf, 1);
	}

	// Call original function

	PuttySend_Original(handle, buf, len, interactive);

	FunctionFlow::UnCheckFlag();
}

// PuttyRecv callback

int PuttyRecv_Callback(void *term, int is_stderr, const char *data, int len)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	signed int ret = PuttyRecv_Original(term, is_stderr, data, len);

	// Do things

	if (bFlag == FALSE)
	{
		if (data != NULL) PluginSystem::ProcessAndSaveRead("PuttyRecvSend.pcap", (unsigned char *)data, len);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SSH_Pktsend - WinSCP send callback

void __fastcall SSH_Pktsend_Callback(int datalen, unsigned char *data)
{
	DWORD pThis = 0;

	// Backup EAX register

#if defined _M_IX86
#ifdef _MSC_VER
	__asm { mov pThis, EAX }
#else 
	register unsigned long eax asm("eax");
	pThis = eax;
#endif
#endif 

	// If allowed

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		if (data != NULL && datalen > 0) PluginSystem::ProcessAndSaveWrite("SSH_RecvSend.pcap", data, datalen);
	}

	// Restore EAX register

#if defined _M_IX86
#ifdef _MSC_VER
	__asm { mov EAX, pThis }
#else 
	eax = pThis;

#endif
#endif

	// Call original function

	SSH_Pktsend_Original(datalen, data);

	FunctionFlow::UnCheckFlag();
}

// SSH_Rdpkt - WinSCP receive callback

int __fastcall SSH_Rdpkt_Callback(int datalen, unsigned char *data)
{
	DWORD pThis = 0;

	// Backup EAX register

#if defined _M_IX86
#ifdef _MSC_VER
	__asm { mov pThis, EAX }
#else 
	register unsigned long eax asm("eax");
	pThis = eax;
#endif 
#endif

	BOOL bFlag = FunctionFlow::CheckFlag();

	// Restore EAX register

#if defined _M_IX86
#ifdef _MSC_VER
	__asm { mov EAX, pThis }
#else 
	eax = pThis;
#endif 
#endif

	int ret = SSH_Rdpkt_Original(datalen, data);

	// Do things

	if (bFlag == FALSE)
	{
		if (data != NULL && datalen > 0) PluginSystem::ProcessAndSaveRead("SSH_RecvSend.pcap", data, datalen);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SecureCRT_Write callback

int __cdecl SecureCRT_Callback(void *pthis, unsigned char **data, DWORD size)
{
	// Stuff required to avoid overwriting ECX

	unsigned char **temp_data = data;
	DWORD temp_size = size;

	BOOL bFlag = FunctionFlow::CheckFlag();

	int ret = SecureCRT_Original(pthis, temp_data, temp_size);

	// Do things

	if (bFlag == FALSE)
	{
		if (*data != NULL) PluginSystem::ProcessAndSaveRead("SecureCRT.pcap", (*data), size);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}
