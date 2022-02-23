// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <stdint.h>
// Format of .BTF and .BTF.ext is documented here:
// https://www.kernel.org/doc/html/latest/bpf/btf.html

#define BTF_KIND_INT 1         /* Integer      */
#define BTF_KIND_PTR 2         /* Pointer      */
#define BTF_KIND_ARRAY 3       /* Array        */
#define BTF_KIND_STRUCT 4      /* Struct       */
#define BTF_KIND_UNION 5       /* Union        */
#define BTF_KIND_ENUM 6        /* Enumeration  */
#define BTF_KIND_FWD 7         /* Forward      */
#define BTF_KIND_TYPEDEF 8     /* Typedef      */
#define BTF_KIND_VOLATILE 9    /* Volatile     */
#define BTF_KIND_CONST 10      /* Const        */
#define BTF_KIND_RESTRICT 11   /* Restrict     */
#define BTF_KIND_FUNC 12       /* Function     */
#define BTF_KIND_FUNC_PROTO 13 /* Function Proto       */
#define BTF_KIND_VAR 14        /* Variable     */
#define BTF_KIND_DATASEC 15    /* Section      */
#define BTF_KIND_FLOAT 16      /* Floating point       */
#define BTF_KIND_DECL_TAG 17   /* Decl Tag     */
#define BTF_KIND_TYPE_TAG 18   /* Type Tag     */

#define BTF_INT_ENCODING(VAL) (((VAL)&0x0f000000) >> 24)
#define BTF_INT_OFFSET(VAL) (((VAL)&0x00ff0000) >> 16)
#define BTF_INT_BITS(VAL) ((VAL)&0x000000ff)

#define BTF_MEMBER_BITFIELD_SIZE(val) ((val) >> 24)
#define BTF_MEMBER_BIT_OFFSET(val) ((val)&0xffffff)

#define BTF_MEMBER_BITFIELD_SIZE(val) ((val) >> 24)
#define BTF_MEMBER_BIT_OFFSET(val) ((val)&0xffffff)

#define BTF_HEADER_MAGIC 0xeB9F
#define BTF_HEADER_VERSION 1

#define BPF_LINE_INFO_LINE_NUM(line_col) ((line_col) >> 10)
#define BPF_LINE_INFO_LINE_COL(line_col) ((line_col)&0x3ff)

typedef struct _btf_header
{
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    uint32_t type_off; /* offset of type section       */
    uint32_t type_len; /* length of type section       */
    uint32_t str_off;  /* offset of string section     */
    uint32_t str_len;  /* length of string section     */
} btf_header_t;

typedef struct _btf_type
{
    uint32_t name_off;
    /* "info" bits arrangement
     * bits  0-15: vlen (e.g. # of struct's members)
     * bits 16-23: unused
     * bits 24-28: kind (e.g. int, ptr, array...etc)
     * bits 29-30: unused
     * bit     31: kind_flag, currently used by
     *             struct, union and fwd
     */
    uint32_t info;
    /* "size" is used by INT, ENUM, STRUCT and UNION.
     * "size" tells the size of the type it is describing.
     *
     * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
     * FUNC, FUNC_PROTO, DECL_TAG and TYPE_TAG.
     * "type" is a type_id referring to another type.
     */
    union
    {
        uint32_t size;
        uint32_t type;
    };
} btf_type_t;

typedef struct _btf_array
{
    uint32_t type;
    uint32_t index_type;
    uint32_t nelems;
} btf_array_t;

typedef struct _btf_param
{
    uint32_t name_off;
    uint32_t type;
} btf_param_t;

typedef struct _btf_var
{
    uint32_t linkage;
} btf_var_t;

typedef struct _btf_var_secinfo
{
    uint32_t type;
    uint32_t offset;
    uint32_t size;
} btf_var_secinfo_t;

typedef struct _btf_decl_tag
{
    uint32_t component_idx;
} btf_decl_tag_t;

typedef struct _btf_ext_header
{
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    uint32_t func_info_off;
    uint32_t func_info_len;
    uint32_t line_info_off;
    uint32_t line_info_len;
} btf_ext_header_t;

#pragma warning(push)
#pragma warning(disable : 4200) // nonstandard extension used: zero-sized array in struct/union
typedef struct _btf_ext_info_sec
{
    uint32_t sec_name_off; /* offset to section name */
    uint32_t num_info;
    /* Followed by num_info * record_size number of bytes */
    uint8_t data[0];
} btf_ext_info_sec_t;
#pragma warning(pop)

typedef struct _bpf_func_info
{
    uint32_t insn_off; /* [0, insn_cnt - 1] */
    uint32_t type_id;  /* pointing to a BTF_KIND_FUNC type */
} bpf_func_info_t;

typedef struct _bpf_line_info
{
    uint32_t insn_off;      /* [0, insn_cnt - 1] */
    uint32_t file_name_off; /* offset to string table for the filename */
    uint32_t line_off;      /* offset to string table for the source line */
    uint32_t line_col;      /* line number and column number */
} bpf_line_info_t;