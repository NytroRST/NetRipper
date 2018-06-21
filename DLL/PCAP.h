
#ifndef _PCAP_H_
#define _PCAP_H_

#include <string>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <vector>
#include <windows.h>
#include "Utils.h"
#include "DebugLog.h"

using namespace std;

#pragma pack(push, 1)

// Tracking seq and ack based in IPs/ports

struct PacketTracker
{
	uint32_t nSeq = 0;
	uint32_t nAck = 0;
	uint32_t nSrcIP = 0x10101010;
	uint32_t nDstIP = 0x20202020;
	uint16_t nSrcPort = 1337;
	uint16_t nDstPort = 80;
};

// Struct used internally

struct PCAPFile
{
	string sFilename;
	bool   bHeaderWritten = 0;
	vector<PacketTracker*> vPacketTrackers;
	CRITICAL_SECTION oCriticalSection;
};

// PCAP header: https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef struct pcap_hdr_s
{
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

// PCAP packet header: https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef struct pcaprec_hdr_s
{
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

// Source https://stackoverflow.com/questions/16519846/parse-ip-and-tcp-header-especially-common-tcp-header-optionsof-packets-capture

typedef struct {
	uint8_t  ver_ihl;  // 4 bits version and 4 bits internet header length
	uint8_t  tos;
	uint16_t total_length;
	uint16_t id;
	uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_header_t;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint16_t len_and_flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} tcp_header_t;

#pragma pack(pop)

// Defines

#define LINKTYPE_IPV4			228
#define PACKET_HEADER_SIZE		40
#define MAX_PACKET_SIZE			65535

// Conversion: http://www.jbox.dk/sanos/source/include/net/inet.h.html

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

// Class to work with PCAP files

class PCAP
{
	// Array containing required info about PCAP files

	static vector<PCAPFile*> s_vPCAPFiles;

	// Internal functions

	static PCAPFile* CreatePCAP(string p_sFilename, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort);
	static PCAPFile* GetPCAP(string p_sFilename, bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort);
	static PacketTracker* GetPacketTracker(PCAPFile *p_pPCAP, bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort);
	static void WriteHeader(PCAPFile *p_pPCAP);
	static pcaprec_hdr_s CreatePacketHeader(size_t nLength);
	static unsigned char* CreatePacket(PCAPFile *p_pPCAP, unsigned char *p_pcData, size_t p_nSize, bool p_bDataSent,
		uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort);
	static void WritePacketData(PCAPFile *p_pPCAP, string p_sFilename, unsigned char *p_pcData, size_t p_nSize, bool p_bDataSent,
		uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort);

public:

	// Main function that does everything

	static void WriteData(string p_sFilename, unsigned char *p_pcData, size_t p_nSize, bool p_bDataSent,
		uint32_t p_sSrcIP = 0x10101010, uint32_t p_sDstIP = 0x20202020, uint16_t p_nSrcPort = 1337, uint16_t p_nDstPort = 80);
};

#endif 
