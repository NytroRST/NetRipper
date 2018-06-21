
#include "stdafx.h"
#include "PCAP.h"

vector<PCAPFile*> PCAP::s_vPCAPFiles;

// Create a PCAP struct

PCAPFile* PCAP::CreatePCAP(string p_sFilepath, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	PCAPFile* pcap = new PCAPFile();
	pcap->sFilename = p_sFilepath;

	pcap->bHeaderWritten = false;
	InitializeCriticalSection(&pcap->oCriticalSection);

	srand((unsigned int)time(NULL));

	// Packet tracker

	PacketTracker *first = new PacketTracker();
	first->nAck = (uint32_t)rand();
	first->nSeq = (uint32_t)rand();

	first->nSrcIP = p_sSrcIP;
	first->nDstIP = p_sDstIP;
	first->nSrcPort = p_nSrcPort;
	first->nDstPort = p_nDstPort;

	pcap->vPacketTrackers.push_back(first);

	s_vPCAPFiles.push_back(pcap);

	return pcap;
}

// Find a PCAP struct by filepath or create it

PCAPFile* PCAP::GetPCAP(string p_sFilename, bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	for (size_t i = 0; i < s_vPCAPFiles.size(); i++)
	{
		if (p_sFilename.compare(s_vPCAPFiles[i]->sFilename) == 0)
		{
			// Create tracker if not there

			bool bFound = false;

			for (size_t p = 0; p < s_vPCAPFiles[i]->vPacketTrackers.size(); p++)
			{
				if ((s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcIP == p_sSrcIP        && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstIP == p_sDstIP &&
						s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcPort == p_nSrcPort && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstPort == p_nDstPort) ||
					(s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcIP == p_sDstIP        && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstIP == p_sSrcIP &&
						s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcPort == p_nDstPort && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstPort == p_nSrcPort))
					bFound = true;
			}

			if (!bFound)
			{
				PacketTracker *newtracker = new PacketTracker();
				newtracker->nAck = (uint32_t)rand();
				newtracker->nSeq = (uint32_t)rand();

				newtracker->nSrcIP = p_sSrcIP;
				newtracker->nDstIP = p_sDstIP;
				newtracker->nSrcPort = p_nSrcPort;
				newtracker->nDstPort = p_nDstPort;

				s_vPCAPFiles[i]->vPacketTrackers.push_back(newtracker);
			}

			return s_vPCAPFiles[i];
		}
	}

	// Or create it

	return CreatePCAP(p_sFilename, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
}

// Write the PCAP file

void PCAP::WriteHeader(PCAPFile *p_pPCAP)
{
	pcap_hdr_s header;

	// Build struct

	header.magic_number = 0xA1B2C3D4;
	header.version_major = 2;
	header.version_minor = 4;
	header.thiszone = 0;
	header.sigfigs = 0;
	header.snaplen = MAX_PACKET_SIZE;
	header.network = LINKTYPE_IPV4;

	// Write the header

	p_pPCAP->bHeaderWritten = true;
	Utils::WriteToTempFile(p_pPCAP->sFilename, (unsigned char *)&header, sizeof(header));
}

// Create packet header

pcaprec_hdr_s PCAP::CreatePacketHeader(size_t nLength)
{
	pcaprec_hdr_s header;
	SYSTEMTIME t;
	GetSystemTime(&t);

	// Create header

	header.ts_sec = (uint32_t)time(NULL);
	header.ts_usec = (uint32_t)(t.wMilliseconds * 1000);
	header.incl_len = (uint32_t)(nLength + 40);
	header.orig_len = (uint32_t)(nLength + 40);

	return header;
}

// Return a packet tracker by IPs/ports

PacketTracker* PCAP::GetPacketTracker(PCAPFile *p_pPCAP, bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	for (size_t i = 0; i < p_pPCAP->vPacketTrackers.size(); i++)
	{
		if( (p_pPCAP->vPacketTrackers[i]->nSrcIP == p_sSrcIP     && p_pPCAP->vPacketTrackers[i]->nDstIP == p_sDstIP &&
				p_pPCAP->vPacketTrackers[i]->nSrcPort == p_nSrcPort && p_pPCAP->vPacketTrackers[i]->nDstPort == p_nDstPort) ||
			(p_pPCAP->vPacketTrackers[i]->nSrcIP == p_sDstIP && p_pPCAP->vPacketTrackers[i]->nDstIP == p_sSrcIP &&
				p_pPCAP->vPacketTrackers[i]->nSrcPort == p_nDstPort && p_pPCAP->vPacketTrackers[i]->nDstPort == p_nSrcPort)
			) return p_pPCAP->vPacketTrackers[i];
	}

	DebugLog::Log("ERROR: GetPacketTracker - PacketTracker not found!");
	return NULL;
}

// Create packet contents, including TCP/IP header (https://github.com/google/ssl_logger/blob/master/ssl_logger.py)

unsigned char* PCAP::CreatePacket(PCAPFile *p_pPCAP, unsigned char *p_pcData, size_t p_nSize,
	bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	ip_header_t  ipHeader;
	tcp_header_t tcpHeader;
	unsigned char *pData = NULL;
	uint32_t seq = 0, ack = 0;

	// Packet tracker

	PacketTracker def;
	PacketTracker *p = GetPacketTracker(p_pPCAP, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	if (p == NULL) p = &def;

	// Get SEQ and ACK

	if (p_bDataSent)
	{
		seq = p->nSeq;
		ack = p->nAck;
	}
	else
	{
		seq = p->nAck;
		ack = p->nSeq;
	}

	// Set up IP header

	ipHeader.ver_ihl = 0x45;
	ipHeader.tos = 0;
	ipHeader.total_length = HTONS((uint16_t)(p_nSize + PACKET_HEADER_SIZE));
	ipHeader.id = 0;
	ipHeader.flags_fo = HTONS(0x4000);
	ipHeader.ttl = 0xFF;
	ipHeader.protocol = 6;
	ipHeader.checksum = 0;

	// IP addresses and TCP ports

	if (!p_bDataSent)
	{
		ipHeader.src_addr = p_sDstIP;
		ipHeader.dst_addr = p_sSrcIP;
		tcpHeader.src_port = HTONS((uint16_t)p_nDstPort);
		tcpHeader.dst_port = HTONS((uint16_t)p_nSrcPort);
	}
	else
	{
		ipHeader.src_addr = p_sSrcIP;
		ipHeader.dst_addr = p_sDstIP;
		tcpHeader.src_port = HTONS((uint16_t)p_nSrcPort);
		tcpHeader.dst_port = HTONS((uint16_t)p_nDstPort);
	}

	// Set up TCP header

	tcpHeader.seq = HTONL(seq);
	tcpHeader.ack = HTONL(ack);

	if (p_bDataSent) tcpHeader.len_and_flags = HTONS(0x5018);
	else tcpHeader.len_and_flags = HTONS(0x5010);

	tcpHeader.window_size = 0xFFFF;
	tcpHeader.checksum = 0;
	tcpHeader.urgent_p = 0;

	// Update SEQ and ACK

	if (p_bDataSent) p->nSeq += (uint32_t)p_nSize;
	else p->nAck += (uint32_t)p_nSize;

	// Create packet

	pData = new unsigned char[sizeof(ipHeader) + sizeof(tcpHeader) + (uint16_t)p_nSize];
	memcpy(pData, (void *)&ipHeader, sizeof(ipHeader));
	memcpy(pData + sizeof(ipHeader), (void *)&tcpHeader, sizeof(tcpHeader));
	memcpy(pData + sizeof(ipHeader) + sizeof(tcpHeader), (void *)p_pcData, (uint16_t)p_nSize);

	return pData;
}

// Write a packet's data

void PCAP::WritePacketData(PCAPFile *p_pPCAP, string p_sFilename, unsigned char *p_pcData, size_t p_nSize, bool p_bDataSent,
	uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	// Packet header 

	pcaprec_hdr_s pheader = CreatePacketHeader(p_nSize);
	Utils::WriteToTempFile(p_sFilename, (unsigned char *)&pheader, sizeof(pheader));

	// Write packet data

	unsigned char *pData = CreatePacket(p_pPCAP, p_pcData, p_nSize, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	Utils::WriteToTempFile(p_sFilename, pData, sizeof(ip_header_t) + sizeof(tcp_header_t) + (uint16_t)p_nSize);
	delete[] pData;
}

// Write data to PCAP file

void PCAP::WriteData(string p_sFilename, unsigned char *p_pcData, size_t p_nSize, bool p_bDataSent,
	uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	PCAPFile *pcap = GetPCAP(p_sFilename, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	size_t size_counter = (size_t)(p_nSize / MAX_PACKET_SIZE);
	size_t size_rest    = (size_t)(p_nSize % MAX_PACKET_SIZE);

	EnterCriticalSection(&pcap->oCriticalSection);

	// Write pcap header (if not written)

	if (pcap->bHeaderWritten == false) WriteHeader(pcap);

	// Write by using maximum 65535 bytes in a packet

	for(size_t i = 0; i < size_counter; i++)
		WritePacketData(pcap, p_sFilename, (unsigned char *)(p_pcData + i * MAX_PACKET_SIZE), MAX_PACKET_SIZE, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	
	if(size_rest) WritePacketData(pcap, p_sFilename, (unsigned char *)(p_pcData + size_counter * MAX_PACKET_SIZE), size_rest, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);

	LeaveCriticalSection(&pcap->oCriticalSection);
}
