#pragma once

#define uint8_t UINT8
#define uint16_t UINT16
#define uint32_t UINT32
#define uint64_t UINT64

typedef struct UDP_HEADER_ {
    UINT16 srcPort;
    UINT16 destPort;
    UINT16 length;
    UINT16 checksum;
} UDP_HEADER;

typedef struct _TCP_HEADER
{
    USHORT SourcePort;
    USHORT DestinationPort;
    ULONG SequenceNumber;
    ULONG AckNumber;
    USHORT OffsetAndFlags;
    USHORT WindowSize;
    USHORT Checksum;
    USHORT UrgentPointer;
} TCP_HEADER, * PTCP_HEADER;