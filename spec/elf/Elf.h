

#ifndef __Elf_H
#define __Elf_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include "EverParse.h"

#define ELF____MAX_UINT32 ((uint32_t)0xffffffffU)

#define ELF____ELFMAG0 ((uint8_t)0x7fU)

#define ELF____ELFMAG1 ((uint8_t)0x45U)

#define ELF____ELFMAG2 ((uint8_t)0x4cU)

#define ELF____ELFMAG3 ((uint8_t)0x46U)

#define ELF____PN_XNUM ((uint16_t)0xffffU)

#define ELF____SHN_LORESERVE ((uint16_t)0xff00U)

#define ELF____SHN_UNDEF ((uint8_t)0U)

/*
Enum constant
*/
#define ELF____ELFCLASSNONE ((uint8_t)0U)

/*
Enum constant
*/
#define ELF____ELFCLASS32 ((uint8_t)1U)

/*
Enum constant
*/
#define ELF____ELFCLASS64 ((uint8_t)2U)

/*
Enum constant
*/
#define ELF____ELFDATANONE ((uint8_t)0U)

/*
Enum constant
*/
#define ELF____ELFDATA2LSB ((uint8_t)1U)

/*
Enum constant
*/
#define ELF____ELFDATA2MSB ((uint8_t)2U)

/*
Enum constant
*/
#define ELF____ELFOSABI_NONE ((uint8_t)0U)

/*
Enum constant
*/
#define ELF____ELFOSABI_SYSV ((uint8_t)1U)

/*
Enum constant
*/
#define ELF____ELFOSABI_HPUX ((uint8_t)2U)

/*
Enum constant
*/
#define ELF____ELFOSABI_NETBSD ((uint8_t)3U)

/*
Enum constant
*/
#define ELF____ELFOSABI_LINUX ((uint8_t)4U)

/*
Enum constant
*/
#define ELF____ELFOSABI_SOLARIS ((uint8_t)5U)

/*
Enum constant
*/
#define ELF____ELFOSABI_IRIX ((uint8_t)6U)

/*
Enum constant
*/
#define ELF____ELFOSABI_FREEBSD ((uint8_t)7U)

/*
Enum constant
*/
#define ELF____ELFOSABI_TRU64 ((uint8_t)8U)

/*
Enum constant
*/
#define ELF____ELFOSABI_ARM ((uint8_t)9U)

/*
Enum constant
*/
#define ELF____ELFOSABI_STANDALONE ((uint8_t)10U)

#define ELF____E_IDENT_PADDING_SIZE ((uint8_t)7U)

/*
Enum constant
*/
#define ELF____ET_NONE ((uint16_t)0U)

/*
Enum constant
*/
#define ELF____ET_REL ((uint16_t)1U)

/*
Enum constant
*/
#define ELF____ET_EXEC ((uint16_t)2U)

/*
Enum constant
*/
#define ELF____ET_DYN ((uint16_t)3U)

/*
Enum constant
*/
#define ELF____ET_CORE ((uint16_t)4U)

#define ELF____SH_NOBITS ((uint8_t)8U)

    uint64_t
    ElfValidateElf(
        uint64_t ElfFileSize,
        uint8_t* Ctxt,
        void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
        uint8_t* Input,
        uint64_t InputLength,
        uint64_t StartPosition);

#if defined(__cplusplus)
}
#endif

#define __Elf_H_DEFINED
#endif
