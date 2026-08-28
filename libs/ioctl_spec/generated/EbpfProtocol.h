

#ifndef __EbpfProtocol_H
#define __EbpfProtocol_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include "EverParse.h"
#define EBPFPROTOCOL____HEADER_SIZE ((uint8_t)8U)

#define EBPFPROTOCOL____HEADER_PAD_SIZE ((uint8_t)2U)

#define EBPFPROTOCOL____MAX_OPERATION_ID ((uint8_t)45U)

#define EBPFPROTOCOL____OP_CREATE_PROGRAM ((uint8_t)2U)

#define EBPFPROTOCOL____OP_CREATE_MAP ((uint8_t)3U)

#define EBPFPROTOCOL____OP_LOAD_CODE ((uint8_t)4U)

#define EBPFPROTOCOL____OP_MAP_FIND_ELEMENT ((uint8_t)5U)

#define EBPFPROTOCOL____OP_MAP_UPDATE_ELEMENT ((uint8_t)6U)

#define EBPFPROTOCOL____OP_MAP_UPDATE_ELEMENT_WITH_HANDLE ((uint8_t)7U)

#define EBPFPROTOCOL____OP_MAP_DELETE_ELEMENT ((uint8_t)8U)

#define EBPFPROTOCOL____OP_MAP_GET_NEXT_KEY ((uint8_t)9U)

#define EBPFPROTOCOL____OP_UPDATE_PINNING ((uint8_t)11U)

#define EBPFPROTOCOL____OP_GET_PINNED_OBJECT ((uint8_t)12U)

#define EBPFPROTOCOL____OP_LINK_PROGRAM ((uint8_t)13U)

#define EBPFPROTOCOL____OP_UNLINK_PROGRAM ((uint8_t)14U)

#define EBPFPROTOCOL____OP_MAP_WRITE_DATA ((uint8_t)30U)

#define EBPFPROTOCOL____OP_LOAD_NATIVE_MODULE ((uint8_t)31U)

#define EBPFPROTOCOL____OP_PROGRAM_TEST_RUN ((uint8_t)33U)

#define EBPFPROTOCOL____OP_MAP_UPDATE_ELEMENT_BATCH ((uint8_t)34U)

#define EBPFPROTOCOL____OP_MAP_DELETE_ELEMENT_BATCH ((uint8_t)35U)

#define EBPFPROTOCOL____OP_MAP_GET_NEXT_KEY_VALUE_BATCH ((uint8_t)36U)

#define EBPFPROTOCOL____OP_GET_NEXT_PINNED_OBJECT_PATH ((uint8_t)38U)

#define EBPFPROTOCOL____EBPF_CODE_TYPE_MAX ((uint8_t)3U)

#define EBPFPROTOCOL____EBPF_MAP_OPTION_MAX ((uint8_t)2U)

#define EBPFPROTOCOL____EBPF_OBJECT_TYPE_MAX ((uint8_t)3U)

#define EBPFPROTOCOL____CREATE_PROGRAM_DATA_OFFSET ((uint8_t)28U)

#define EBPFPROTOCOL____CREATE_MAP_DATA_OFFSET ((uint8_t)40U)

#define EBPFPROTOCOL____LOAD_CODE_CODE_OFFSET ((uint8_t)20U)

#define EBPFPROTOCOL____FIND_ELEMENT_KEY_OFFSET ((uint8_t)17U)

#define EBPFPROTOCOL____MAP_UPDATE_DATA_OFFSET ((uint8_t)20U)

#define EBPFPROTOCOL____MAP_UPDATE_WITH_HANDLE_KEY_OFFSET ((uint8_t)28U)

#define EBPFPROTOCOL____DELETE_ELEMENT_KEY_OFFSET ((uint8_t)16U)

#define EBPFPROTOCOL____GET_NEXT_KEY_PREVIOUS_KEY_OFFSET ((uint8_t)16U)

#define EBPFPROTOCOL____UPDATE_PINNING_PATH_OFFSET ((uint8_t)16U)

#define EBPFPROTOCOL____GET_PINNED_OBJECT_PATH_OFFSET ((uint8_t)8U)

#define EBPFPROTOCOL____LINK_PROGRAM_DATA_OFFSET ((uint8_t)32U)

#define EBPFPROTOCOL____UNLINK_PROGRAM_DATA_OFFSET ((uint8_t)41U)

#define EBPFPROTOCOL____MAP_WRITE_DATA_DATA_OFFSET ((uint8_t)24U)

#define EBPFPROTOCOL____LOAD_NATIVE_MODULE_DATA_OFFSET ((uint8_t)24U)

#define EBPFPROTOCOL____PROGRAM_TEST_RUN_DATA_OFFSET ((uint8_t)42U)

#define EBPFPROTOCOL____DELETE_ELEMENT_BATCH_KEYS_OFFSET ((uint8_t)16U)

#define EBPFPROTOCOL____GET_NEXT_KEY_VALUE_BATCH_KEY_OFFSET ((uint8_t)17U)

#define EBPFPROTOCOL____PINNED_OBJECT_PATH_START_PATH_OFFSET ((uint8_t)12U)

    uint64_t
    EbpfProtocolValidateEbpfIoctlMessage(
        uint32_t BufferLength,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

#if defined(__cplusplus)
}
#endif

#define __EbpfProtocol_H_DEFINED
#endif
