
#ifndef _HOOKEDFUNCTIONS_H_
#define _HOOKEDFUNCTIONS_H_

#define SECURITY_WIN32

#include "Utils.h"
#include "DebugLog.h"
#include "FunctionFlow.h"
#include "PluginSystem.h"
#include "MinHook.h"
#include <winsock2.h>
#include <security.h>
#include <stdio.h>

// =============================================================================================//

// PR_Read, PR_Write, SSLGetSessionID

typedef int (*PR_Write_Typedef)(void *, void *, DWORD);
typedef int (*PR_Read_Typedef)(void *, void *, DWORD);
typedef int (*PR_GetDescType_Typedef)(void *fd);

// Callbacks

int PR_Write_Callback(void *fd, void *buffer, DWORD amount);
int PR_Read_Callback(void *fd, void *buffer, DWORD amount);

// =============================================================================================//

// SSL_Read, SSL_Write

typedef int (*SSL_Write_Typedef)(void *, void *, int);
typedef int (*SSL_Read_Typedef)(void *, void *, int);

// Callbacks

int SSL_Write_Callback(void *ssl, void *buffer, int amount);
int SSL_Read_Callback(void *ssl, void *buffer, int amount);

// =============================================================================================//

// SSLEay_Read, SSLEay_Write

typedef int(*SSLeay_Write_Typedef)(void *, void *, int);
typedef int(*SSLeay_Read_Typedef)(void *, void *, int);

// Callbacks

int SSLeay_Write_Callback(void *ssl, void *buffer, int amount);
int SSLeay_Read_Callback(void *ssl, void *buffer, int amount);

// =============================================================================================//

// SecureCRT_Write

typedef int(__stdcall *SecureCRT_Typedef)(void *pthis, unsigned char **data, DWORD);

// Callback

int __cdecl SecureCRT_Callback(void *pthis, unsigned char **data, DWORD size);

// =============================================================================================//

// PuttySend, PuttyRecv

typedef void (*PuttySend_Typedef)(void *handle, char *buf, int len, int interactive);
typedef int (*PuttyRecv_Typedef)(void *term, int is_stderr, const char *data, int len);

// Callbacks

void PuttySend_Callback(void *handle, char *buf, int len, int interactive);
int PuttyRecv_Callback(void *term, int is_stderr, const char *data, int len);

// =============================================================================================//

// PR_Send, PR_Recv

typedef int (*PR_Send_Typedef)(void *fd, const void *buf, int amount, int flags, DWORD timeout);
typedef int (*PR_Recv_Typedef)(void *fd, void *buf, int amount, int flags, DWORD timeout);

// Callbacks

int PR_Send_Callback(void *fd, const void *buf, int amount, int flags, DWORD timeout);
int PR_Recv_Callback(void *fd, void *buf, int amount, int flags, DWORD timeout);

// =============================================================================================//

// SSH_Rdpkt

typedef int (__fastcall *SSH_Rdpkt_Typedef)(int datalen, unsigned char *data);
typedef void (__fastcall *SSH_Pktsend_Typedef)(int datalen, unsigned char *data);

// Callbacks

int __fastcall SSH_Rdpkt_Callback(int datalen, unsigned char *data);
void __fastcall SSH_Pktsend_Callback(int datalen, unsigned char *data);

// =============================================================================================//

// SslEncryptPacket, SslDecryptPacket

typedef LONG (__stdcall *SslEncryptPacket_Typedef)(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput, 
	PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwContentType, DWORD dwFlags);
typedef LONG (__stdcall *SslDecryptPacket_Typedef)(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput,
	PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwFlags);

// Callbacks

LONG __stdcall SslEncryptPacket_Callback(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput,  PBYTE pbOutput, 
	DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwContentType, DWORD dwFlags);
LONG __stdcall SslDecryptPacket_Callback(ULONG_PTR hSslProvider, ULONG_PTR hKey, PBYTE *pbInput, DWORD cbInput, PBYTE pbOutput, 
	DWORD cbOutput, DWORD *pcbResult, ULONGLONG SequenceNumber, DWORD dwFlags);

// =============================================================================================//

// send, recv

typedef int (__stdcall *send_Typedef)(int s, char *buf, int len, int flags);
typedef int (__stdcall *recv_Typedef)(int s, char *buf, int len, int flags);

// Callbacks

int __stdcall send_Callback(int s, char *buf, int len, int flags);
int __stdcall recv_Callback(int s, char *buf, int len, int flags);

// =============================================================================================//

// WSASend, WSARecv

typedef int (__stdcall *WSASend_Typedef)(int s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, 
	DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (__stdcall *WSARecv_Typedef)(int s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, 
	LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// Callbacks

int __stdcall WSASend_Callback(int s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, 
	DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int __stdcall WSARecv_Callback(int s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, 
	LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// =============================================================================================//

// EncryptMessage, DecryptMessage

typedef SECURITY_STATUS (__stdcall *EncryptMessage_Typedef)(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo);
typedef SECURITY_STATUS (__stdcall *DecryptMessage_Typedef)(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP);

// Callbacks

SECURITY_STATUS __stdcall EncryptMessage_Callback(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo);
SECURITY_STATUS __stdcall DecryptMessage_Callback(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP);

// =============================================================================================//

// Variables (function pointers)

extern PR_Write_Typedef PR_Write_Original;
extern PR_Read_Typedef PR_Read_Original;
extern PR_GetDescType_Typedef PR_GetDescType_Original;

extern SSL_Write_Typedef SSL_Write_Original;
extern SSL_Read_Typedef SSL_Read_Original;

extern SSLeay_Write_Typedef SSLeay_Write_Original;
extern SSLeay_Read_Typedef SSLeay_Read_Original;

extern PR_Send_Typedef PR_Send_Original;
extern PR_Recv_Typedef PR_Recv_Original;

extern SSH_Pktsend_Typedef SSH_Pktsend_Original;
extern SSH_Rdpkt_Typedef SSH_Rdpkt_Original;

extern SslEncryptPacket_Typedef SslEncryptPacket_Original;
extern SslDecryptPacket_Typedef SslDecryptPacket_Original;

extern send_Typedef send_Original;
extern recv_Typedef recv_Original;

extern WSASend_Typedef WSASend_Original;
extern WSARecv_Typedef WSARecv_Original;

extern EncryptMessage_Typedef EncryptMessage_Original;
extern DecryptMessage_Typedef DecryptMessage_Original;

extern PuttySend_Typedef PuttySend_Original;
extern PuttyRecv_Typedef PuttyRecv_Original;

extern SecureCRT_Typedef SecureCRT_Original;

// =============================================================================================//

#endif
