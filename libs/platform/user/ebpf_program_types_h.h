

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


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



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#include "midles.h"

#ifndef __ebpf_program_types_h_h__
#define __ebpf_program_types_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __ebpf_program_types_INTERFACE_DEFINED__
#define __ebpf_program_types_INTERFACE_DEFINED__

/* interface ebpf_program_types */
/* [explicit_handle] */ 

typedef unsigned int uint32_t;

typedef unsigned long long uint64_t;

#pragma once
typedef 
enum _ebpf_helper_return_type
    {
        EBPF_RETURN_TYPE_INTEGER	= 0,
        EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL	= ( EBPF_RETURN_TYPE_INTEGER + 1 ) ,
        EBPF_RETURN_TYPE_VOID	= ( EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL + 1 ) 
    } 	ebpf_helper_return_type_t;

typedef 
enum _ebpf_helper_argument_type
    {
        EBPF_ARGUMENT_TYPE_DONTCARE	= 0,
        EBPF_ARGUMENT_TYPE_ANYTHING	= ( EBPF_ARGUMENT_TYPE_DONTCARE + 1 ) ,
        EBPF_ARGUMENT_TYPE_CONST_SIZE	= ( EBPF_ARGUMENT_TYPE_ANYTHING + 1 ) ,
        EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO	= ( EBPF_ARGUMENT_TYPE_CONST_SIZE + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_CTX	= ( EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP	= ( EBPF_ARGUMENT_TYPE_PTR_TO_CTX + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY	= ( EBPF_ARGUMENT_TYPE_PTR_TO_MAP + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE	= ( EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM	= ( EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL	= ( EBPF_ARGUMENT_TYPE_PTR_TO_MEM + 1 ) ,
        EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM	= ( EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL + 1 ) 
    } 	ebpf_helper_argument_type_t;

typedef struct _ebpf_context_descriptor
    {
    int size;
    int data;
    int end;
    int meta;
    } 	ebpf_context_descriptor_t;

typedef struct _ebpf_program_type_descriptor
    {
    /* [string] */ const unsigned char *name;
    ebpf_context_descriptor_t *context_descriptor;
    uint64_t platform_specific_data;
    unsigned char is_privileged;
    } 	ebpf_program_type_descriptor_t;

typedef struct _ebpf_helper_function_prototype
    {
    uint32_t helper_id;
    /* [string] */ const unsigned char *name;
    ebpf_helper_return_type_t return_type;
    ebpf_helper_argument_type_t arguments[ 5 ];
    } 	ebpf_helper_function_prototype_t;

typedef struct _ebpf_program_information
    {
    ebpf_program_type_descriptor_t program_type_descriptor;
    uint32_t count_of_helpers;
    /* [size_is] */ ebpf_helper_function_prototype_t *helper_prototype;
    } 	ebpf_program_information_t;

typedef /* [allocate][decode][encode] */ ebpf_program_information_t *ebpf_program_information_pointer_t;



extern RPC_IF_HANDLE ebpf_program_types_v0_0_c_ifspec;
extern RPC_IF_HANDLE ebpf_program_types_v0_0_s_ifspec;
#endif /* __ebpf_program_types_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */


size_t
ebpf_program_information_pointer_t_AlignSize(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType);


void
ebpf_program_information_pointer_t_Encode(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType);


void
ebpf_program_information_pointer_t_Decode(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType);


void
ebpf_program_information_pointer_t_Free(
    handle_t _MidlEsHandle,
    ebpf_program_information_pointer_t * _pType);

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


