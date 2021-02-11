// clang -O2 -Wall -c droppacket.c -o dropjit.o
// 
// For bpf code: clang -target bpf -O2 -Wall -c droppacket.c -o droppacket.o
// this passes the checker

#pragma clang section text="xdp"

// define based on linux
typedef unsigned long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

static inline __u16 ntohs(__u16 us)
{
    return us << 8 | us >> 8;
}

typedef struct xdp_md_
{
   __u64 data;
   __u64 data_end;
   __u64 data_meta;
} xdp_md;

typedef struct _IPV4_HEADER {
    union {
        __u8 VersionAndHeaderLength;   // Version and header length.
        struct {
            __u8 HeaderLength : 4;
            __u8 Version : 4;
        };
    };
    union {
        __u8 TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
        struct {
            __u8 EcnField : 2;
            __u8 TypeOfService : 6;
        };
    };
    __u16 TotalLength;                 // Total length of datagram.
    __u16 Identification;
    union {
        __u16 FlagsAndOffset;          // Flags and fragment offset.
        struct {
            __u16 DontUse1 : 5;        // High bits of fragment offset.
            __u16 MoreFragments : 1;
            __u16 DontFragment : 1;
            __u16 Reserved : 1;
            __u16 DontUse2 : 8;        // Low bits of fragment offset.
        };
    };
    __u8 TimeToLive;
    __u8 Protocol;
    __u16 HeaderChecksum;
    __u32 SourceAddress;
    __u32 DestinationAddress;
} IPV4_HEADER, *PIPV4_HEADER;

typedef struct UDP_HEADER_ {
    __u16 srcPort;
    __u16 destPort;
    __u16 length;
    __u16 checksum;
} UDP_HEADER;


int DropPacket(xdp_md* ctx)
{
      void *data_end = (void *)(long long)ctx->data_end;
      void *data = (void *)(long long)ctx->data;
      UDP_HEADER* udphdr;
      IPV4_HEADER* iphdr = data;
      int rc = 1;
      if ((char *)data + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) > (char *)data_end)
           goto Done;

      // udp
      if (iphdr->Protocol == 17)
      {
          udphdr = (UDP_HEADER* )(iphdr  + 1);
          if (ntohs(udphdr->length) <= sizeof(UDP_HEADER))
          {
              rc = 2;
          }
      }
Done:
      return rc;     
}