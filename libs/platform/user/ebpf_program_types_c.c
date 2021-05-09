

/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 20:14:07 2038
 */
/* Compiler settings for ..\ebpf_program_types.idl, ..\ebpf_program_types.acf:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)


#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#include <string.h>

#include "ebpf_program_types_h.h"

#define TYPE_FORMAT_STRING_SIZE   121                               
#define PROC_FORMAT_STRING_SIZE   1                                 
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _ebpf_program_types_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } ebpf_program_types_MIDL_TYPE_FORMAT_STRING;

typedef struct _ebpf_program_types_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } ebpf_program_types_MIDL_PROC_FORMAT_STRING;

typedef struct _ebpf_program_types_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } ebpf_program_types_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};


extern const ebpf_program_types_MIDL_TYPE_FORMAT_STRING ebpf_program_types__MIDL_TypeFormatString;
extern const ebpf_program_types_MIDL_PROC_FORMAT_STRING ebpf_program_types__MIDL_ProcFormatString;
extern const ebpf_program_types_MIDL_EXPR_FORMAT_STRING ebpf_program_types__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Pickling interface: ebpf_program_types, ver. 0.0,
   GUID={0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}} */



static const RPC_CLIENT_INTERFACE ebpf_program_types___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}},{0,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000
    };
RPC_IF_HANDLE ebpf_program_types_v0_0_c_ifspec = (RPC_IF_HANDLE)& ebpf_program_types___RpcClientInterface;

extern const MIDL_STUB_DESC ebpf_program_types_StubDesc;

static RPC_BINDING_HANDLE ebpf_program_types__MIDL_AutoBindHandle;

static const MIDL_TYPE_PICKLING_INFO __MIDL_TypePicklingInfo =
    {
    0x33205054, /* Signature & version: TP 1 */
    0x3, /* Flags: Oicf NewCorrDesc */
    0,
    0,
    0,
    };

size_t
ebpf_program_information_pointer_t_AlignSize(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType)
{
    return NdrMesTypeAlignSize2(
                        _MidlEsHandle,
                        ( PMIDL_TYPE_PICKLING_INFO  )&__MIDL_TypePicklingInfo,
                        &ebpf_program_types_StubDesc,
                        ( PFORMAT_STRING  )&ebpf_program_types__MIDL_TypeFormatString.Format[2],
                        _pType);
}

void
ebpf_program_information_pointer_t_Encode(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType)
{
    NdrMesTypeEncode2(
                     _MidlEsHandle,
                     ( PMIDL_TYPE_PICKLING_INFO  )&__MIDL_TypePicklingInfo,
                     &ebpf_program_types_StubDesc,
                     ( PFORMAT_STRING  )&ebpf_program_types__MIDL_TypeFormatString.Format[2],
                     _pType);
}

void
ebpf_program_information_pointer_t_Decode(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType)
{
    NdrMesTypeDecode2(
                     _MidlEsHandle,
                     ( PMIDL_TYPE_PICKLING_INFO  )&__MIDL_TypePicklingInfo,
                     &ebpf_program_types_StubDesc,
                     ( PFORMAT_STRING  )&ebpf_program_types__MIDL_TypeFormatString.Format[2],
                     _pType);
}

void
ebpf_program_information_pointer_t_Free(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType)
{
    NdrMesTypeFree2(
                   _MidlEsHandle,
                   ( PMIDL_TYPE_PICKLING_INFO  )&__MIDL_TypePicklingInfo,
                   &ebpf_program_types_StubDesc,
                   ( PFORMAT_STRING  )&ebpf_program_types__MIDL_TypeFormatString.Format[2],
                   _pType);
}


#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const ebpf_program_types_MIDL_PROC_FORMAT_STRING ebpf_program_types__MIDL_ProcFormatString =
    {
        0,
        {

			0x0
        }
    };

static const ebpf_program_types_MIDL_TYPE_FORMAT_STRING ebpf_program_types__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x1,	/* FC_UP [all_nodes] */
/*  4 */	NdrFcShort( 0x60 ),	/* Offset= 96 (100) */
/*  6 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/*  8 */	NdrFcShort( 0x10 ),	/* 16 */
/* 10 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 12 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 14 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 16 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 18 */	NdrFcShort( 0x20 ),	/* 32 */
/* 20 */	NdrFcShort( 0x0 ),	/* 0 */
/* 22 */	NdrFcShort( 0x8 ),	/* Offset= 8 (30) */
/* 24 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 26 */	0xb,		/* FC_HYPER */
			0x2,		/* FC_CHAR */
/* 28 */	0x43,		/* FC_STRUCTPAD7 */
			0x5b,		/* FC_END */
/* 30 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 32 */	
			0x22,		/* FC_C_CSTRING */
			0x5c,		/* FC_PAD */
/* 34 */	
			0x12, 0x0,	/* FC_UP */
/* 36 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (6) */
/* 38 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x1,		/* 1 */
/* 40 */	NdrFcShort( 0x5 ),	/* 5 */
/* 42 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 46 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 48 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 52 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 54 */	0xd,		/* FC_ENUM16 */
			0x5b,		/* FC_END */
/* 56 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 58 */	NdrFcShort( 0x28 ),	/* 40 */
/* 60 */	NdrFcShort( 0x0 ),	/* 0 */
/* 62 */	NdrFcShort( 0xc ),	/* Offset= 12 (74) */
/* 64 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 66 */	0x36,		/* FC_POINTER */
			0xd,		/* FC_ENUM16 */
/* 68 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 70 */	NdrFcShort( 0xffe0 ),	/* Offset= -32 (38) */
/* 72 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 74 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 76 */	
			0x22,		/* FC_C_CSTRING */
			0x5c,		/* FC_PAD */
/* 78 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 80 */	NdrFcShort( 0x0 ),	/* 0 */
/* 82 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 84 */	NdrFcShort( 0x20 ),	/* 32 */
/* 86 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 88 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 92 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 94 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 96 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (56) */
/* 98 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 100 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 102 */	NdrFcShort( 0x30 ),	/* 48 */
/* 104 */	NdrFcShort( 0x0 ),	/* 0 */
/* 106 */	NdrFcShort( 0xa ),	/* Offset= 10 (116) */
/* 108 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 110 */	NdrFcShort( 0xffa2 ),	/* Offset= -94 (16) */
/* 112 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 114 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 116 */	
			0x12, 0x20,	/* FC_UP [maybenull_sizeis] */
/* 118 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (78) */

			0x0
        }
    };

static const unsigned short ebpf_program_types_FormatStringOffsetTable[] =
    {
    0
    };


static const MIDL_STUB_DESC ebpf_program_types_StubDesc = 
    {
    (void *)& ebpf_program_types___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &ebpf_program_types__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    ebpf_program_types__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x60001, /* Ndr library version */
    0,
    0x801026e, /* MIDL Version 8.1.622 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x1, /* MIDL flag */
    0, /* cs routines */
    0,   /* proxy/server info */
    0
    };
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* defined(_M_AMD64)*/

