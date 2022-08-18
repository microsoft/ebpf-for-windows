// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "kernel_thunk.h"
#include "ndis_thunk.h"

typedef void* FWPS_CALLOUT_CLASSIFY_FN;
typedef void* FWPS_CALLOUT_NOTIFY_FN;
typedef void* FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN;

// 94c44912-9d6f-4ebf-b995-05ab8a088d1b
DEFINE_GUID(
    FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE, 0x94c44912, 0x9d6f, 0x4ebf, 0xb9, 0x95, 0x05, 0xab, 0x8a, 0x08, 0x8d, 0x1b);

// d4220bd3-62ce-4f08-ae88-b56e8526df50
DEFINE_GUID(
    FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, 0xd4220bd3, 0x62ce, 0x4f08, 0xae, 0x88, 0xb5, 0x6e, 0x85, 0x26, 0xdf, 0x50);

// 1247d66d-0b60-4a15-8d44-7155d0f53a0c
DEFINE_GUID(
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, 0x1247d66d, 0x0b60, 0x4a15, 0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c);

// 74365cce-ccb0-401a-bfc1-b89934ad7e15
DEFINE_GUID(
    FWPM_LAYER_ALE_RESOURCE_RELEASE_V4, 0x74365cce, 0xccb0, 0x401a, 0xbf, 0xc1, 0xb8, 0x99, 0x34, 0xad, 0x7e, 0x15);

// 55a650e1-5f0a-4eca-a653-88f53b26aa8c
DEFINE_GUID(
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, 0x55a650e1, 0x5f0a, 0x4eca, 0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c);

// f4e5ce80-edcc-4e13-8a2f-b91454bb057b
DEFINE_GUID(
    FWPM_LAYER_ALE_RESOURCE_RELEASE_V6, 0xf4e5ce80, 0xedcc, 0x4e13, 0x8a, 0x2f, 0xb9, 0x14, 0x54, 0xbb, 0x05, 0x7b);

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0x4a72393b, 0x319f, 0x44bc, 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4);

// a3b42c97-9f04-4672-b87e-cee9c483257f
DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 0xa3b42c97, 0x9f04, 0x4672, 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f);

// af80470a-5596-4c13-9992-539e6fe57967
DEFINE_GUID(
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, 0xaf80470a, 0x5596, 0x4c13, 0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67);

// 7021d2b3-dfa4-406e-afeb-6afaf7e70efd
DEFINE_GUID(
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, 0x7021d2b3, 0xdfa4, 0x406e, 0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd);

// e1cd9fe7-f4b5-4273-96c0-592e487b8650
DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, 0xe1cd9fe7, 0xf4b5, 0x4273, 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50);

// 35A791AB-04AC-4FF2-A6BB-DA6CFAC71806
DEFINE_GUID(FWPM_CONDITION_COMPARTMENT_ID, 0x35a791ab, 0x4ac, 0x4ff2, 0xa6, 0xbb, 0xda, 0x6c, 0xfa, 0xc7, 0x18, 0x6);

// 667fd755-d695-434a-8af5-d3835a1259bc
DEFINE_GUID(FWPM_CONDITION_INTERFACE_INDEX, 0x667fd755, 0xd695, 0x434a, 0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc);

#define FWPS_INCOMING_METADATA_VALUES FWPS_INCOMING_METADATA_VALUES0

// Provides additional meta-information to the filter engine. This information
// is not processed by the filter engine, but is supplied to the callouts.
// Unlike the FWPS_INCOMING_VALUES0, the schema of the meta-information is not
// fixed. Callouts should not assume that a given FWPS_METADATA_FIELD is
// present or that it is located at a given index in the array.

typedef struct FWPS_INCOMING_METADATA_VALUES0_
{
    // Bitmask representing which values are set.
    UINT32 currentMetadataValues;
    // Internal flags;
    UINT32 flags;
    // Reserved for system use.
    UINT64 reserved;
    // Discard module and reason.
    FWPS_DISCARD_METADATA0 discardMetadata;
    // Flow Handle.
    UINT64 flowHandle;
    // IP Header size.
    UINT32 ipHeaderSize;
    // Transport Header size
    UINT32 transportHeaderSize;
    // Process Path.
    FWP_BYTE_BLOB* processPath;
    // Token used for authorization.
    UINT64 token;
    // Process Id.
    UINT64 processId;
    // Source and Destination interface indices for discard indications.
    UINT32 sourceInterfaceIndex;
    UINT32 destinationInterfaceIndex;
    // Compartment Id for injection APIs.
    ULONG compartmentId;
    // Fragment data for inbound fragments.
    FWPS_INBOUND_FRAGMENT_METADATA0 fragmentMetadata;
    // Path MTU for outbound packets (to enable calculation of fragments).
    ULONG pathMtu;
    // Completion handle (required in order to be able to pend at this layer).
    HANDLE completionHandle;
    // Endpoint handle for use in outbound transport layer injection.
    UINT64 transportEndpointHandle;
    // Remote scope id for use in outbound transport layer injection.
    SCOPE_ID remoteScopeId;
    // Socket control data (and length) for use in outbound transport layer injection.
    WSACMSGHDR* controlData;
    ULONG controlDataLength;
    // Direction for the current packet. Only specified for ALE re-authorization.
    FWP_DIRECTION packetDirection;
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    // Raw IP header (and length) if the packet is sent with IP header from a RAW socket.
    void* headerIncludeHeader;
    ULONG headerIncludeHeaderLength;
#if (NTDDI_VERSION >= NTDDI_WIN7)
    IP_ADDRESS_PREFIX destinationPrefix;
    UINT16 frameLength;
    UINT64 parentEndpointHandle;
    UINT32 icmpIdAndSequence;
    // PID of the process that will be accepting the redirected connection
    DWORD localRedirectTargetPID;
    // original destination of a redirected connection
    SOCKADDR* originalDestination;
#if (NTDDI_VERSION >= NTDDI_WIN8)
    HANDLE redirectRecords;
    // Bitmask representing which L2 values are set.
    UINT32 currentL2MetadataValues;
    // L2 layer flags;
    UINT32 l2Flags;
    UINT32 ethernetMacHeaderSize;
    UINT32 wiFiOperationMode;

#if (NDIS_SUPPORT_NDIS630)
    NDIS_SWITCH_PORT_ID vSwitchSourcePortId;
    NDIS_SWITCH_NIC_INDEX vSwitchSourceNicIndex;
    NDIS_SWITCH_PORT_ID vSwitchDestinationPortId;
#else
    UINT32 padding0;
    USHORT padding1;
    UINT32 padding2;
#endif // (NDIS_SUPPORT_NDIS630)
    HANDLE vSwitchPacketContext;
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN8)
    void* subProcessTag;
    // Reserved for system use.
    UINT64 reserved1;
#endif
} FWPS_INCOMING_METADATA_VALUES0;

///////////////////////////////////////////////////////////////////////////////
//
// LUIDs for built-in layers.
//
///////////////////////////////////////////////////////////////////////////////

typedef enum FWPS_BUILTIN_LAYERS_
{
    // Kernel-mode layers
    FWPS_LAYER_INBOUND_IPPACKET_V4, // 0
    FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD,
    FWPS_LAYER_INBOUND_IPPACKET_V6,
    FWPS_LAYER_INBOUND_IPPACKET_V6_DISCARD,
    FWPS_LAYER_OUTBOUND_IPPACKET_V4,
    FWPS_LAYER_OUTBOUND_IPPACKET_V4_DISCARD, // 5
    FWPS_LAYER_OUTBOUND_IPPACKET_V6,
    FWPS_LAYER_OUTBOUND_IPPACKET_V6_DISCARD,
    FWPS_LAYER_IPFORWARD_V4,
    FWPS_LAYER_IPFORWARD_V4_DISCARD,
    FWPS_LAYER_IPFORWARD_V6, // 10
    FWPS_LAYER_IPFORWARD_V6_DISCARD,
    FWPS_LAYER_INBOUND_TRANSPORT_V4,
    FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD,
    FWPS_LAYER_INBOUND_TRANSPORT_V6,
    FWPS_LAYER_INBOUND_TRANSPORT_V6_DISCARD, // 15
    FWPS_LAYER_OUTBOUND_TRANSPORT_V4,
    FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD,
    FWPS_LAYER_OUTBOUND_TRANSPORT_V6,
    FWPS_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD,
    FWPS_LAYER_STREAM_V4, // 20
    FWPS_LAYER_STREAM_V4_DISCARD,
    FWPS_LAYER_STREAM_V6,
    FWPS_LAYER_STREAM_V6_DISCARD,
    FWPS_LAYER_DATAGRAM_DATA_V4,
    FWPS_LAYER_DATAGRAM_DATA_V4_DISCARD, // 25
    FWPS_LAYER_DATAGRAM_DATA_V6,
    FWPS_LAYER_DATAGRAM_DATA_V6_DISCARD,
    FWPS_LAYER_INBOUND_ICMP_ERROR_V4,
    FWPS_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD,
    FWPS_LAYER_INBOUND_ICMP_ERROR_V6, // 30
    FWPS_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD,
    FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4,
    FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD,
    FWPS_LAYER_OUTBOUND_ICMP_ERROR_V6,
    FWPS_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD, // 35
    FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
    FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD,
    FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD,
    FWPS_LAYER_ALE_AUTH_LISTEN_V4, // 40
    FWPS_LAYER_ALE_AUTH_LISTEN_V4_DISCARD,
    FWPS_LAYER_ALE_AUTH_LISTEN_V6,
    FWPS_LAYER_ALE_AUTH_LISTEN_V6_DISCARD,
    FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD, // 45
    FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD,
    FWPS_LAYER_ALE_AUTH_CONNECT_V4,
    FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD,
    FWPS_LAYER_ALE_AUTH_CONNECT_V6, // 50
    FWPS_LAYER_ALE_AUTH_CONNECT_V6_DISCARD,
    FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4,
    FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD,
    FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6,
    FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD, // 55
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET,
    FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
#if (NTDDI_VERSION == NTDDI_WIN7)
    FWPS_LAYER_RESERVED1_V4,
    FWPS_LAYER_RESERVED1_V6,
#else
    FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE,
    FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
#endif
    FWPS_LAYER_NAME_RESOLUTION_CACHE_V4, // 60
    FWPS_LAYER_NAME_RESOLUTION_CACHE_V6,
    FWPS_LAYER_ALE_RESOURCE_RELEASE_V4,
    FWPS_LAYER_ALE_RESOURCE_RELEASE_V6,
    FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4,
    FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6, // 65
    FWPS_LAYER_ALE_CONNECT_REDIRECT_V4,
    FWPS_LAYER_ALE_CONNECT_REDIRECT_V6,
    FWPS_LAYER_ALE_BIND_REDIRECT_V4,
    FWPS_LAYER_ALE_BIND_REDIRECT_V6,
    FWPS_LAYER_STREAM_PACKET_V4, // 70
    FWPS_LAYER_STREAM_PACKET_V6,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_LAYER_INGRESS_VSWITCH_ETHERNET,
    FWPS_LAYER_EGRESS_VSWITCH_ETHERNET,
    FWPS_LAYER_INGRESS_VSWITCH_TRANSPORT_V4,
    FWPS_LAYER_INGRESS_VSWITCH_TRANSPORT_V6, // 75
    FWPS_LAYER_EGRESS_VSWITCH_TRANSPORT_V4,
    FWPS_LAYER_EGRESS_VSWITCH_TRANSPORT_V6,
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
    FWPS_LAYER_INBOUND_TRANSPORT_FAST,
    FWPS_LAYER_OUTBOUND_TRANSPORT_FAST,
    FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST, // 80
    FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)
    FWPS_LAYER_INBOUND_RESERVED2,
#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
    FWPS_LAYER_RESERVED_LAYER_9,
    FWPS_LAYER_RESERVED_LAYER_10,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_FE)
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS3)
#endif // (NTDDI_VERSION >= NTDDI_WINBLUE)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
    // User-mode layers
    FWPS_LAYER_IPSEC_KM_DEMUX_V4, // 85
    FWPS_LAYER_IPSEC_KM_DEMUX_V6,
    FWPS_LAYER_IPSEC_V4,
    FWPS_LAYER_IPSEC_V6,
    FWPS_LAYER_IKEEXT_V4,
    FWPS_LAYER_IKEEXT_V6, // 90
    FWPS_LAYER_RPC_UM,
    FWPS_LAYER_RPC_EPMAP,
    FWPS_LAYER_RPC_EP_ADD,
    FWPS_LAYER_RPC_PROXY_CONN,
    FWPS_LAYER_RPC_PROXY_IF, // 95
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_LAYER_KM_AUTHORIZATION,
#endif                      // (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_BUILTIN_LAYER_MAX, // 97
} FWPS_BUILTIN_LAYERS;

// Version-1 of run-time state necessary to invoke a callout.
typedef struct FWPS_CALLOUT3_
{
    // Uniquely identifies the callout. This must be the same GUID supplied to
    // FwpmCalloutAdd0.
    GUID calloutKey;
    // flags
    UINT32 flags;
    // Pointer to the classification function.
    FWPS_CALLOUT_CLASSIFY_FN3 classifyFn;
    // Pointer to the notification function.
    FWPS_CALLOUT_NOTIFY_FN3 notifyFn;
    // Pointer to the flow delete function.
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn;
} FWPS_CALLOUT3;

typedef enum FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_
{
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_USER_ID,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_PROMISCUOUS_MODE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_FLAGS,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_INTERFACE_TYPE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_TUNNEL_TYPE,
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_LOCAL_INTERFACE_PROFILE_ID,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_SIO_FIREWALL_SOCKET_PROPERTY,
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif //(NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_RESERVED_0,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_RESERVED_1,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_MAX
} FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4;

typedef enum FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V6_
{
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_APP_ID,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_USER_ID,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_PROTOCOL,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_PROMISCUOUS_MODE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_FLAGS,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_INTERFACE_TYPE,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_TUNNEL_TYPE,
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_LOCAL_INTERFACE_PROFILE_ID,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_SIO_FIREWALL_SOCKET_PROPERTY,
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif //(NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_RESERVED_0,
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_RESERVED_1,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_MAX
} FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V6;

typedef enum FWPS_FIELDS_ALE_RESOURCE_RELEASE_V4_
{
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_USER_ID,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_PROTOCOL,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_FLAGS,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif //(NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_MAX
} FWPS_FIELDS_ALE_RESOURCE_RELEASE_V4;

typedef enum FWPS_FIELDS_ALE_RESOURCE_RELEASE_V6_
{
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_ALE_APP_ID,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_ALE_USER_ID,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_PROTOCOL,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_FLAGS,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif //(NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_MAX
} FWPS_FIELDS_ALE_RESOURCE_RELEASE_V6;

typedef enum FWPS_FIELDS_ALE_AUTH_CONNECT_V4_
{
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_REMOTE_USER_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_REMOTE_MACHINE_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_DESTINATION_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_TUNNEL_TYPE,
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX,
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_ARRIVAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ARRIVAL_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ARRIVAL_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ARRIVAL_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_SUB_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_NEXTHOP_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ORIGINAL_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_CURRENT_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_REAUTHORIZE_REASON,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_PEER_NAME,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ORIGINAL_ICMP_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_QUARANTINE_EPOCH,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_ORIGINAL_APP_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_EFFECTIVE_NAME,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif // (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_RESERVED_0,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_RESERVED_1,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_RESERVED_2,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_RESERVED_3,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_MAX
} FWPS_FIELDS_ALE_AUTH_CONNECT_V4;

typedef enum FWPS_FIELDS_ALE_AUTH_CONNECT_V6_
{
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_USER_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_REMOTE_USER_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_REMOTE_MACHINE_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_DESTINATION_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_TUNNEL_TYPE,
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_SUB_INTERFACE_INDEX,
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_ARRIVAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ARRIVAL_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ARRIVAL_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ARRIVAL_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_NEXTHOP_SUB_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_NEXTHOP_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_NEXTHOP_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_NEXTHOP_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_NEXTHOP_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ORIGINAL_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_CURRENT_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_REAUTHORIZE_REASON,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_PEER_NAME,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ORIGINAL_ICMP_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_QUARANTINE_EPOCH,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_ORIGINAL_APP_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_EFFECTIVE_NAME,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif // (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_RESERVED_0,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_RESERVED_1,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_RESERVED_2,
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_RESERVED_3,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_AUTH_CONNECT_V6_MAX
} FWPS_FIELDS_ALE_AUTH_CONNECT_V6;

typedef enum FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_
{
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_USER_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_REMOTE_USER_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_REMOTE_MACHINE_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SIO_FIREWALL_SYSTEM_PORT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NAP_CONTEXT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_TYPE,      // of local/delivery interface
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_TUNNEL_TYPE,         // of local/delivery interface
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX,     // of local/delivery interface
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX, // of arrival interface
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_ARRIVAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_INTERFACE_INDEX,
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_SUB_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_NEXTHOP_INTERFACE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ORIGINAL_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_CURRENT_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_REAUTHORIZE_REASON,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ORIGINAL_ICMP_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_QUARANTINE_EPOCH,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif // (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_RESERVED_0,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_RESERVED_1,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_RESERVED_2,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_RESERVED_3,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_MAX
} FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4;

typedef enum FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V6_
{
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_USER_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_REMOTE_USER_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_REMOTE_MACHINE_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SIO_FIREWALL_SYSTEM_PORT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_NAP_CONTEXT,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_TYPE,      // of local/delivery interface
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_TUNNEL_TYPE,         // of local/delivery interface
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX,     // of local/delivery interface
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX, // of arrival interface
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_ARRIVAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ARRIVAL_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ARRIVAL_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ARRIVAL_INTERFACE_INDEX,
#if (NTDDI_VERSION >= NTDDI_WIN7)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_NEXTHOP_SUB_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_NEXTHOP_INTERFACE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_NEXTHOP_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_NEXTHOP_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_NEXTHOP_INTERFACE_INDEX,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ORIGINAL_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_CURRENT_PROFILE_ID,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_REAUTHORIZE_REASON,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ORIGINAL_ICMP_TYPE,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_QUARANTINE_EPOCH,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif // (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_RESERVED_0,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_RESERVED_1,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_RESERVED_2,
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_RESERVED_3,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_MAX
} FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V6;

typedef enum FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_
{
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_USER_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_REMOTE_USER_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_REMOTE_MACHINE_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_DESTINATION_ADDRESS_TYPE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_INTERFACE_TYPE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_TUNNEL_TYPE,
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_ORIGINAL_APP_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif // (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_RESERVED_0,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_RESERVED_1,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_RESERVED_2,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_RESERVED_3,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_MAX
} FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4;

typedef enum FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6_
{
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_USER_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS_TYPE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_REMOTE_USER_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_REMOTE_MACHINE_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_DESTINATION_ADDRESS_TYPE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_INTERFACE_TYPE,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_TUNNEL_TYPE,
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_FLAGS,
#if (NTDDI_VERSION >= NTDDI_WIN8)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_ORIGINAL_APP_ID,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_PACKAGE_ID,
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#endif // (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN6SP1)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_RESERVED_0,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_RESERVED_1,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_RESERVED_2,
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_RESERVED_3,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)
    FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_MAX
} FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V6;

typedef enum FWPS_FIELDS_INBOUND_MAC_FRAME_NATIVE_
{
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_MEDIA_TYPE,
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PHYSICAL_MEDIA_TYPE,
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE,
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_TYPE,
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX,
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PORT,
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_L2_FLAGS,
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_COMPARTMENT_ID,
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS2)
    FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_MAX
} FWPS_FIELDS_INBOUND_MAC_FRAME_NATIVE;

#define FWPS_INJECTION_TYPE_L2 0x00000010

NTSTATUS
FwpmFilterDeleteById0(_In_ HANDLE engine_handle, _In_ UINT64 id);

NTSTATUS
FwpmTransactionBegin0(_In_ _Acquires_lock_(_Curr_) HANDLE engine_handle, _In_ UINT32 flags);

NTSTATUS
FwpmFilterAdd0(
    _In_ HANDLE engine_handle, _In_ const FWPM_FILTER0* filter, _In_opt_ PSECURITY_DESCRIPTOR sd, _Out_opt_ UINT64* id);

NTSTATUS
FwpmTransactionCommit0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle);

NTSTATUS
FwpmTransactionAbort0(_In_ _Releases_lock_(_Curr_) HANDLE engine_handle);

NTSTATUS
FwpsCalloutRegister3(_Inout_ void* device_object, _In_ const FWPS_CALLOUT3* callout, _Out_opt_ UINT32* callout_id);

NTSTATUS
FwpmCalloutAdd0(
    _In_ HANDLE engine_handle,
    _In_ const FWPM_CALLOUT0* callout,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ UINT32* id);

NTSTATUS
FwpsCalloutUnregisterById0(_In_ const UINT32 callout_id);

NTSTATUS
FwpmEngineOpen0(
    _In_opt_ const wchar_t* server_name,
    _In_ UINT32 authn_service,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* auth_identity,
    _In_opt_ const FWPM_SESSION0* session,
    _Out_ HANDLE* engine_handle);

NTSTATUS
FwpmSubLayerAdd0(_In_ HANDLE engine_handle, _In_ const FWPM_SUBLAYER0* sub_layer, _In_opt_ PSECURITY_DESCRIPTOR sd);

NTSTATUS
FwpsInjectionHandleCreate0(_In_opt_ ADDRESS_FAMILY address_family, _In_ UINT32 flags, _Out_ HANDLE* injection_handle);

NTSTATUS
FwpmEngineClose0(_Inout_ HANDLE engine_handle);

NTSTATUS
FwpsInjectionHandleDestroy0(_In_ HANDLE injection_handle);

NTSTATUS
FwpsFlowRemoveContext0(_In_ UINT64 flowI_id, _In_ UINT16 layer_id, _In_ UINT32 callout_id);

NTSTATUS

FwpsFlowAssociateContext0(_In_ UINT64 flowI_id, _In_ UINT16 layer_id, _In_ UINT32 callout_id, _In_ UINT64 flow_context);

NTSTATUS
FwpsAllocateNetBufferAndNetBufferList0(
    _In_ NDIS_HANDLE pool_handle,
    _In_ USHORT context_size,
    _In_ USHORT context_backfill,
    _In_opt_ MDL* mdl_chain,
    _In_ ULONG data_offset,
    _In_ SIZE_T data_length,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list);

void
FwpsFreeNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list);

NTSTATUS
FwpsInjectMacReceiveAsync0(
    _In_ HANDLE injection_handle,
    _In_opt_ HANDLE injection_context,
    _In_ UINT32 flags,
    _In_ UINT16 layer_id,
    _In_ IF_INDEX interface_index,
    _In_ NDIS_PORT_NUMBER ndis_port_number,
    _Inout_ NET_BUFFER_LIST* net_buffer_lists,
    _In_ void* completion_function,
    _In_opt_ HANDLE completion_context);

void
FwpsFreeCloneNetBufferList0(_In_ NET_BUFFER_LIST* net_buffer_list, _In_ ULONG free_clone_flags);

NTSTATUS
FwpsAllocateCloneNetBufferList0(
    _Inout_ NET_BUFFER_LIST* original_net_buffer_list,
    _In_opt_ NDIS_HANDLE net_buffer_list_pool_handle,
    _In_opt_ NDIS_HANDLE net_buffer_pool_handle,
    _In_ ULONG allocate_clone_flags,
    _Outptr_ NET_BUFFER_LIST** net_buffer_list);

NTSTATUS
FwpsInjectMacSendAsync0(
    _In_ HANDLE injection_handle,
    _In_opt_ HANDLE injection_context,
    _In_ UINT32 flags,
    _In_ UINT16 layer_id,
    _In_ IF_INDEX interface_index,
    _In_ NDIS_PORT_NUMBER ndis_port_number,
    _Inout_ NET_BUFFER_LIST* net_buffer_lists,
    _In_ void* completion_function,
    _In_opt_ HANDLE completion_context);