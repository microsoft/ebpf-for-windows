

#include "Elf.h"

static inline uint64_t
ValidateZeroByte(
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    /* Validating field zero */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterzero_refinement;
    if (hasBytes) {
        positionAfterzero_refinement = StartPosition + (uint64_t)1U;
    } else {
        positionAfterzero_refinement =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterZeroByte;
    if (EverParseIsError(positionAfterzero_refinement)) {
        positionAfterZeroByte = positionAfterzero_refinement;
    } else {
        /* reading field_value */
        uint8_t zero_refinement = Input[(uint32_t)StartPosition];
        /* start: checking constraint */
        BOOLEAN zero_refinementConstraintIsOk = zero_refinement == (uint8_t)0U;
        /* end: checking constraint */
        positionAfterZeroByte = EverParseCheckConstraintOk(zero_refinementConstraintIsOk, positionAfterzero_refinement);
    }
    if (EverParseIsSuccess(positionAfterZeroByte)) {
        return positionAfterZeroByte;
    }
    Err("_ZeroByte",
        "zero.refinement",
        EverParseErrorReasonOfResult(positionAfterZeroByte),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterZeroByte;
}

static inline uint64_t
ValidateEIdent(
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfternone;
    if (hasBytes0) {
        positionAfternone = StartPosition + (uint64_t)1U;
    } else {
        positionAfternone = EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterEIdent;
    if (EverParseIsError(positionAfternone)) {
        positionAfterEIdent = positionAfternone;
    } else {
        uint8_t none = Input[(uint32_t)StartPosition];
        BOOLEAN noneConstraintIsOk = none == ELF____ELFMAG0;
        uint64_t positionAfternone1 = EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1)) {
            positionAfterEIdent = positionAfternone1;
        } else {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0) {
                positionAfternone2 = positionAfternone1 + (uint64_t)1U;
            } else {
                positionAfternone2 =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
            }
            uint64_t positionAfterEIdent0;
            if (EverParseIsError(positionAfternone2)) {
                positionAfterEIdent0 = positionAfternone2;
            } else {
                uint8_t none1 = Input[(uint32_t)positionAfternone1];
                BOOLEAN noneConstraintIsOk1 = none1 == ELF____ELFMAG1;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3)) {
                    positionAfterEIdent0 = positionAfternone3;
                } else {
                    /* Checking that we have enough space for a UINT8, i.e., 1
                     * byte */
                    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfternone3);
                    uint64_t positionAfternone4;
                    if (hasBytes0) {
                        positionAfternone4 = positionAfternone3 + (uint64_t)1U;
                    } else {
                        positionAfternone4 = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone3);
                    }
                    uint64_t positionAfterEIdent;
                    if (EverParseIsError(positionAfternone4)) {
                        positionAfterEIdent = positionAfternone4;
                    } else {
                        uint8_t none2 = Input[(uint32_t)positionAfternone3];
                        BOOLEAN noneConstraintIsOk2 = none2 == ELF____ELFMAG2;
                        uint64_t positionAfternone5 =
                            EverParseCheckConstraintOk(noneConstraintIsOk2, positionAfternone4);
                        if (EverParseIsError(positionAfternone5)) {
                            positionAfterEIdent = positionAfternone5;
                        } else {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfternone5);
                            uint64_t positionAfternone6;
                            if (hasBytes0) {
                                positionAfternone6 = positionAfternone5 + (uint64_t)1U;
                            } else {
                                positionAfternone6 = EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone5);
                            }
                            uint64_t positionAfterEIdent0;
                            if (EverParseIsError(positionAfternone6)) {
                                positionAfterEIdent0 = positionAfternone6;
                            } else {
                                uint8_t none3 = Input[(uint32_t)positionAfternone5];
                                BOOLEAN noneConstraintIsOk3 = none3 == ELF____ELFMAG3;
                                uint64_t positionAfternone7 =
                                    EverParseCheckConstraintOk(noneConstraintIsOk3, positionAfternone6);
                                if (EverParseIsError(positionAfternone7)) {
                                    positionAfterEIdent0 = positionAfternone7;
                                } else {
                                    /* Checking that we have enough space for a
                                     * UINT8, i.e., 1 byte */
                                    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfternone7);
                                    uint64_t positionAfternone8;
                                    if (hasBytes0) {
                                        positionAfternone8 = positionAfternone7 + (uint64_t)1U;
                                    } else {
                                        positionAfternone8 = EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone7);
                                    }
                                    uint64_t positionAfterEIdent;
                                    if (EverParseIsError(positionAfternone8)) {
                                        positionAfterEIdent = positionAfternone8;
                                    } else {
                                        uint8_t none4 = Input[(uint32_t)positionAfternone7];
                                        BOOLEAN
                                        noneConstraintIsOk4 =
                                            none4 == ELF____ELFCLASS64 &&
                                            (ELF____ELFCLASSNONE == none4 || ELF____ELFCLASS32 == none4 ||
                                             ELF____ELFCLASS64 == none4);
                                        uint64_t positionAfternone9 =
                                            EverParseCheckConstraintOk(noneConstraintIsOk4, positionAfternone8);
                                        if (EverParseIsError(positionAfternone9)) {
                                            positionAfterEIdent = positionAfternone9;
                                        } else {
                                            /* This 3d spec applies to 64-bit
                                             * only currently */
                                            /* Checking that we have enough
                                             * space for a UINT8, i.e., 1 byte
                                             */
                                            BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfternone9);
                                            uint64_t positionAfterFIVE_refinement;
                                            if (hasBytes0) {
                                                positionAfterFIVE_refinement = positionAfternone9 + (uint64_t)1U;
                                            } else {
                                                positionAfterFIVE_refinement = EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone9);
                                            }
                                            uint64_t positionAfterEIdent0;
                                            if (EverParseIsError(positionAfterFIVE_refinement)) {
                                                positionAfterEIdent0 = positionAfterFIVE_refinement;
                                            } else {
                                                /* reading field_value */
                                                uint8_t fIVE_refinement = Input[(uint32_t)positionAfternone9];
                                                /* start: checking constraint */
                                                BOOLEAN
                                                fIVE_refinementConstraintIsOk = ELF____ELFDATANONE == fIVE_refinement ||
                                                                                ELF____ELFDATA2LSB == fIVE_refinement ||
                                                                                ELF____ELFDATA2MSB == fIVE_refinement;
                                                /* end: checking constraint */
                                                positionAfterEIdent0 = EverParseCheckConstraintOk(
                                                    fIVE_refinementConstraintIsOk, positionAfterFIVE_refinement);
                                            }
                                            uint64_t positionAfterFIVE_refinement0;
                                            if (EverParseIsSuccess(positionAfterEIdent0)) {
                                                positionAfterFIVE_refinement0 = positionAfterEIdent0;
                                            } else {
                                                Err("_E_IDENT",
                                                    "FIVE.refinement",
                                                    EverParseErrorReasonOfResult(positionAfterEIdent0),
                                                    Ctxt,
                                                    Input,
                                                    positionAfternone9);
                                                positionAfterFIVE_refinement0 = positionAfterEIdent0;
                                            }
                                            if (EverParseIsError(positionAfterFIVE_refinement0)) {
                                                positionAfterEIdent = positionAfterFIVE_refinement0;
                                            } else {
                                                /* Checking that we have enough
                                                 * space for a UINT8, i.e., 1
                                                 * byte */
                                                BOOLEAN
                                                hasBytes0 =
                                                    (uint64_t)1U <= (InputLength - positionAfterFIVE_refinement0);
                                                uint64_t positionAfternone10;
                                                if (hasBytes0) {
                                                    positionAfternone10 = positionAfterFIVE_refinement0 + (uint64_t)1U;
                                                } else {
                                                    positionAfternone10 = EverParseSetValidatorErrorPos(
                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                        positionAfterFIVE_refinement0);
                                                }
                                                uint64_t positionAfterEIdent0;
                                                if (EverParseIsError(positionAfternone10)) {
                                                    positionAfterEIdent0 = positionAfternone10;
                                                } else {
                                                    uint8_t none5 = Input[(uint32_t)positionAfterFIVE_refinement0];
                                                    BOOLEAN
                                                    noneConstraintIsOk5 = none5 == (uint8_t)1U;
                                                    uint64_t positionAfternone11 = EverParseCheckConstraintOk(
                                                        noneConstraintIsOk5, positionAfternone10);
                                                    if (EverParseIsError(positionAfternone11)) {
                                                        positionAfterEIdent0 = positionAfternone11;
                                                    } else {
                                                        /* ELF specification
                                                         * version is always set
                                                         * to 1 */
                                                        /* Checking that we have
                                                         * enough space for a
                                                         * UINT8, i.e., 1 byte
                                                         */
                                                        BOOLEAN hasBytes0 =
                                                            (uint64_t)1U <= (InputLength - positionAfternone11);
                                                        uint64_t positionAfterSEVEN_refinement;
                                                        if (hasBytes0) {
                                                            positionAfterSEVEN_refinement =
                                                                positionAfternone11 + (uint64_t)1U;
                                                        } else {
                                                            positionAfterSEVEN_refinement =
                                                                EverParseSetValidatorErrorPos(
                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    positionAfternone11);
                                                        }
                                                        uint64_t positionAfterEIdent;
                                                        if (EverParseIsError(positionAfterSEVEN_refinement)) {
                                                            positionAfterEIdent = positionAfterSEVEN_refinement;
                                                        } else {
                                                            /* reading
                                                             * field_value */
                                                            uint8_t sEVEN_refinement =
                                                                Input[(uint32_t)positionAfternone11];
                                                            /* start: checking
                                                             * constraint */
                                                            BOOLEAN
                                                            sEVEN_refinementConstraintIsOk =
                                                                ELF____ELFOSABI_NONE == sEVEN_refinement ||
                                                                ELF____ELFOSABI_SYSV == sEVEN_refinement ||
                                                                ELF____ELFOSABI_HPUX == sEVEN_refinement ||
                                                                ELF____ELFOSABI_NETBSD == sEVEN_refinement ||
                                                                ELF____ELFOSABI_LINUX == sEVEN_refinement ||
                                                                ELF____ELFOSABI_SOLARIS == sEVEN_refinement ||
                                                                ELF____ELFOSABI_IRIX == sEVEN_refinement ||
                                                                ELF____ELFOSABI_FREEBSD == sEVEN_refinement ||
                                                                ELF____ELFOSABI_TRU64 == sEVEN_refinement ||
                                                                ELF____ELFOSABI_ARM == sEVEN_refinement ||
                                                                ELF____ELFOSABI_STANDALONE == sEVEN_refinement;
                                                            /* end: checking
                                                             * constraint */
                                                            positionAfterEIdent = EverParseCheckConstraintOk(
                                                                sEVEN_refinementConstraintIsOk,
                                                                positionAfterSEVEN_refinement);
                                                        }
                                                        uint64_t positionAfterSEVEN_refinement0;
                                                        if (EverParseIsSuccess(positionAfterEIdent)) {
                                                            positionAfterSEVEN_refinement0 = positionAfterEIdent;
                                                        } else {
                                                            Err("_E_IDENT",
                                                                "SEVEN."
                                                                "refinement",
                                                                EverParseErrorReasonOfResult(positionAfterEIdent),
                                                                Ctxt,
                                                                Input,
                                                                positionAfternone11);
                                                            positionAfterSEVEN_refinement0 = positionAfterEIdent;
                                                        }
                                                        if (EverParseIsError(positionAfterSEVEN_refinement0)) {
                                                            positionAfterEIdent0 = positionAfterSEVEN_refinement0;
                                                        } else {
                                                            /* Validating field
                                                             * EIGHT */
                                                            /* Checking that we
                                                             * have enough space
                                                             * for a UINT8,
                                                             * i.e., 1 byte */
                                                            BOOLEAN
                                                            hasBytes = (uint64_t)1U <=
                                                                       (InputLength - positionAfterSEVEN_refinement0);
                                                            uint64_t positionAfterEIGHT_refinement;
                                                            if (hasBytes) {
                                                                positionAfterEIGHT_refinement =
                                                                    positionAfterSEVEN_refinement0 + (uint64_t)1U;
                                                            } else {
                                                                positionAfterEIGHT_refinement =
                                                                    EverParseSetValidatorErrorPos(
                                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                        positionAfterSEVEN_refinement0);
                                                            }
                                                            uint64_t positionAfterEIdent;
                                                            if (EverParseIsError(positionAfterEIGHT_refinement)) {
                                                                positionAfterEIdent = positionAfterEIGHT_refinement;
                                                            } else {
                                                                /* reading
                                                                 * field_value
                                                                 */
                                                                uint8_t eIGHT_refinement =
                                                                    Input[(uint32_t)positionAfterSEVEN_refinement0];
                                                                /* start:
                                                                 * checking
                                                                 * constraint */
                                                                BOOLEAN
                                                                eIGHT_refinementConstraintIsOk =
                                                                    eIGHT_refinement == (uint8_t)0U;
                                                                /* end: checking
                                                                 * constraint */
                                                                positionAfterEIdent = EverParseCheckConstraintOk(
                                                                    eIGHT_refinementConstraintIsOk,
                                                                    positionAfterEIGHT_refinement);
                                                            }
                                                            uint64_t positionAfterEIGHT_refinement0;
                                                            if (EverParseIsSuccess(positionAfterEIdent)) {
                                                                positionAfterEIGHT_refinement0 = positionAfterEIdent;
                                                            } else {
                                                                Err("_E_IDENT",
                                                                    "EIGHT."
                                                                    "refinemen"
                                                                    "t",
                                                                    EverParseErrorReasonOfResult(positionAfterEIdent),
                                                                    Ctxt,
                                                                    Input,
                                                                    positionAfterSEVEN_refinement0);
                                                                positionAfterEIGHT_refinement0 = positionAfterEIdent;
                                                            }
                                                            if (EverParseIsError(positionAfterEIGHT_refinement0)) {
                                                                positionAfterEIdent0 = positionAfterEIGHT_refinement0;
                                                            } else {
                                                                /* ABI version,
                                                                 * always set to
                                                                 * 0 */
                                                                BOOLEAN
                                                                hasEnoughBytes =
                                                                    (uint64_t)(uint32_t)ELF____E_IDENT_PADDING_SIZE <=
                                                                    (InputLength - positionAfterEIGHT_refinement0);
                                                                uint64_t positionAfterEIdent;
                                                                if (!hasEnoughBytes) {
                                                                    positionAfterEIdent = EverParseSetValidatorErrorPos(
                                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                        positionAfterEIGHT_refinement0);
                                                                } else {
                                                                    uint8_t* truncatedInput = Input;
                                                                    uint64_t truncatedInputLength =
                                                                        positionAfterEIGHT_refinement0 +
                                                                        (uint64_t)(uint32_t)ELF____E_IDENT_PADDING_SIZE;
                                                                    uint64_t result = positionAfterEIGHT_refinement0;
                                                                    while (TRUE) {
                                                                        uint64_t position = *&result;
                                                                        BOOLEAN
                                                                        ite;
                                                                        if (!((uint64_t)1U <=
                                                                              (truncatedInputLength - position))) {
                                                                            ite = TRUE;
                                                                        } else {
                                                                            uint64_t positionAfterEIdent =
                                                                                ValidateZeroByte(
                                                                                    Ctxt,
                                                                                    Err,
                                                                                    truncatedInput,
                                                                                    truncatedInputLength,
                                                                                    position);
                                                                            uint64_t result1;
                                                                            if (EverParseIsSuccess(
                                                                                    positionAfterEIdent)) {
                                                                                result1 = positionAfterEIdent;
                                                                            } else {
                                                                                Err("_E_IDENT",
                                                                                    "NINE_FIFTEEN.element",
                                                                                    EverParseErrorReasonOfResult(
                                                                                        positionAfterEIdent),
                                                                                    Ctxt,
                                                                                    truncatedInput,
                                                                                    position);
                                                                                result1 = positionAfterEIdent;
                                                                            }
                                                                            result = result1;
                                                                            ite = EverParseIsError(result1);
                                                                        }
                                                                        if (ite) {
                                                                            break;
                                                                        }
                                                                    }
                                                                    uint64_t res = result;
                                                                    positionAfterEIdent = res;
                                                                }
                                                                if (EverParseIsSuccess(positionAfterEIdent)) {
                                                                    positionAfterEIdent0 = positionAfterEIdent;
                                                                } else {
                                                                    Err("_E_"
                                                                        "IDENT",
                                                                        "NINE_"
                                                                        "FIFTEE"
                                                                        "N",
                                                                        EverParseErrorReasonOfResult(
                                                                            positionAfterEIdent),
                                                                        Ctxt,
                                                                        Input,
                                                                        positionAfterEIGHT_refinement0);
                                                                    positionAfterEIdent0 = positionAfterEIdent;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if (EverParseIsSuccess(positionAfterEIdent0)) {
                                                    positionAfterEIdent = positionAfterEIdent0;
                                                } else {
                                                    Err("_E_IDENT",
                                                        "none",
                                                        EverParseErrorReasonOfResult(positionAfterEIdent0),
                                                        Ctxt,
                                                        Input,
                                                        positionAfterFIVE_refinement0);
                                                    positionAfterEIdent = positionAfterEIdent0;
                                                }
                                            }
                                        }
                                    }
                                    if (EverParseIsSuccess(positionAfterEIdent)) {
                                        positionAfterEIdent0 = positionAfterEIdent;
                                    } else {
                                        Err("_E_IDENT",
                                            "none",
                                            EverParseErrorReasonOfResult(positionAfterEIdent),
                                            Ctxt,
                                            Input,
                                            positionAfternone7);
                                        positionAfterEIdent0 = positionAfterEIdent;
                                    }
                                }
                            }
                            if (EverParseIsSuccess(positionAfterEIdent0)) {
                                positionAfterEIdent = positionAfterEIdent0;
                            } else {
                                Err("_E_IDENT",
                                    "none",
                                    EverParseErrorReasonOfResult(positionAfterEIdent0),
                                    Ctxt,
                                    Input,
                                    positionAfternone5);
                                positionAfterEIdent = positionAfterEIdent0;
                            }
                        }
                    }
                    if (EverParseIsSuccess(positionAfterEIdent)) {
                        positionAfterEIdent0 = positionAfterEIdent;
                    } else {
                        Err("_E_IDENT",
                            "none",
                            EverParseErrorReasonOfResult(positionAfterEIdent),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        positionAfterEIdent0 = positionAfterEIdent;
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterEIdent0)) {
                positionAfterEIdent = positionAfterEIdent0;
            } else {
                Err("_E_IDENT",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterEIdent0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterEIdent = positionAfterEIdent0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterEIdent)) {
        return positionAfterEIdent;
    }
    Err("_E_IDENT", "none", EverParseErrorReasonOfResult(positionAfterEIdent), Ctxt, Input, StartPosition);
    return positionAfterEIdent;
}

static inline uint64_t
ValidateProgramHeaderTableEntry(
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    /* Validating field P_TYPE */
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes0 = (uint64_t)4U <= (InputLength - StartPosition);
    uint64_t positionAfterProgramHeaderTableEntry;
    if (hasBytes0) {
        positionAfterProgramHeaderTableEntry = StartPosition + (uint64_t)4U;
    } else {
        positionAfterProgramHeaderTableEntry =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry)) {
        res0 = positionAfterProgramHeaderTableEntry;
    } else {
        Err("_PROGRAM_HEADER_TABLE_ENTRY",
            "P_TYPE",
            EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry),
            Ctxt,
            Input,
            StartPosition);
        res0 = positionAfterProgramHeaderTableEntry;
    }
    uint64_t positionAfterPType = res0;
    if (EverParseIsError(positionAfterPType)) {
        return positionAfterPType;
    }
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes1 = (uint64_t)4U <= (InputLength - positionAfterPType);
    uint64_t positionAfternone;
    if (hasBytes1) {
        positionAfternone = positionAfterPType + (uint64_t)4U;
    } else {
        positionAfternone =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterPType);
    }
    uint64_t positionAfterProgramHeaderTableEntry0;
    if (EverParseIsError(positionAfternone)) {
        positionAfterProgramHeaderTableEntry0 = positionAfternone;
    } else {
        uint32_t none = Load32Le(Input + (uint32_t)positionAfterPType);
        BOOLEAN noneConstraintIsOk = none <= (uint32_t)(uint8_t)7U;
        uint64_t positionAfternone1 = EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1)) {
            positionAfterProgramHeaderTableEntry0 = positionAfternone1;
        } else {
            /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
            BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfternone1);
            uint64_t positionAfterProgramHeaderTableEntry;
            if (hasBytes0) {
                positionAfterProgramHeaderTableEntry = positionAfternone1 + (uint64_t)8U;
            } else {
                positionAfterProgramHeaderTableEntry =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
            }
            uint64_t positionAfterPOffset;
            if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry)) {
                positionAfterPOffset = positionAfterProgramHeaderTableEntry;
            } else {
                Err("_PROGRAM_HEADER_TABLE_ENTRY",
                    "P_OFFSET",
                    EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterPOffset = positionAfterProgramHeaderTableEntry;
            }
            if (EverParseIsError(positionAfterPOffset)) {
                positionAfterProgramHeaderTableEntry0 = positionAfterPOffset;
            } else {
                uint64_t pOffset = Load64Le(Input + (uint32_t)positionAfternone1);
                /* Validating field P_VADDR */
                /* Checking that we have enough space for a UINT64, i.e., 8
                 * bytes */
                BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfterPOffset);
                uint64_t positionAfterProgramHeaderTableEntry;
                if (hasBytes0) {
                    positionAfterProgramHeaderTableEntry = positionAfterPOffset + (uint64_t)8U;
                } else {
                    positionAfterProgramHeaderTableEntry =
                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterPOffset);
                }
                uint64_t res0;
                if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry)) {
                    res0 = positionAfterProgramHeaderTableEntry;
                } else {
                    Err("_PROGRAM_HEADER_TABLE_ENTRY",
                        "P_VADDR",
                        EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry),
                        Ctxt,
                        Input,
                        positionAfterPOffset);
                    res0 = positionAfterProgramHeaderTableEntry;
                }
                uint64_t positionAfterPVaddr = res0;
                if (EverParseIsError(positionAfterPVaddr)) {
                    positionAfterProgramHeaderTableEntry0 = positionAfterPVaddr;
                } else {
                    /* Validating field P_PADDR */
                    /* Checking that we have enough space for a UINT64, i.e., 8
                     * bytes */
                    BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfterPVaddr);
                    uint64_t positionAfterProgramHeaderTableEntry;
                    if (hasBytes0) {
                        positionAfterProgramHeaderTableEntry = positionAfterPVaddr + (uint64_t)8U;
                    } else {
                        positionAfterProgramHeaderTableEntry = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterPVaddr);
                    }
                    uint64_t res0;
                    if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry)) {
                        res0 = positionAfterProgramHeaderTableEntry;
                    } else {
                        Err("_PROGRAM_HEADER_TABLE_ENTRY",
                            "P_PADDR",
                            EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry),
                            Ctxt,
                            Input,
                            positionAfterPVaddr);
                        res0 = positionAfterProgramHeaderTableEntry;
                    }
                    uint64_t positionAfterPPaddr = res0;
                    if (EverParseIsError(positionAfterPPaddr)) {
                        positionAfterProgramHeaderTableEntry0 = positionAfterPPaddr;
                    } else {
                        /* Checking that we have enough space for a UINT64,
                         * i.e., 8 bytes */
                        BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfterPPaddr);
                        uint64_t positionAfternone2;
                        if (hasBytes0) {
                            positionAfternone2 = positionAfterPPaddr + (uint64_t)8U;
                        } else {
                            positionAfternone2 = EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterPPaddr);
                        }
                        uint64_t positionAfterProgramHeaderTableEntry;
                        if (EverParseIsError(positionAfternone2)) {
                            positionAfterProgramHeaderTableEntry = positionAfternone2;
                        } else {
                            uint64_t none1 = Load64Le(Input + (uint32_t)positionAfterPPaddr);
                            BOOLEAN noneConstraintIsOk1 = none1 < ElfFileSize && pOffset <= (ElfFileSize - none1);
                            uint64_t positionAfternone3 =
                                EverParseCheckConstraintOk(noneConstraintIsOk1, positionAfternone2);
                            if (EverParseIsError(positionAfternone3)) {
                                positionAfterProgramHeaderTableEntry = positionAfternone3;
                            } else {
                                /* Validating field P_MEMSZ */
                                /* Checking that we have enough space for a
                                 * UINT64, i.e., 8 bytes */
                                BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfternone3);
                                uint64_t positionAfterProgramHeaderTableEntry0;
                                if (hasBytes0) {
                                    positionAfterProgramHeaderTableEntry0 = positionAfternone3 + (uint64_t)8U;
                                } else {
                                    positionAfterProgramHeaderTableEntry0 = EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone3);
                                }
                                uint64_t res0;
                                if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry0)) {
                                    res0 = positionAfterProgramHeaderTableEntry0;
                                } else {
                                    Err("_PROGRAM_HEADER_TABLE_ENTRY",
                                        "P_MEMSZ",
                                        EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry0),
                                        Ctxt,
                                        Input,
                                        positionAfternone3);
                                    res0 = positionAfterProgramHeaderTableEntry0;
                                }
                                uint64_t positionAfterPMemsz = res0;
                                if (EverParseIsError(positionAfterPMemsz)) {
                                    positionAfterProgramHeaderTableEntry = positionAfterPMemsz;
                                } else {
                                    /* Validating field P_ALIGN */
                                    /* Checking that we have enough space for a
                                     * UINT64, i.e., 8 bytes */
                                    BOOLEAN hasBytes = (uint64_t)8U <= (InputLength - positionAfterPMemsz);
                                    uint64_t positionAfterProgramHeaderTableEntry0;
                                    if (hasBytes) {
                                        positionAfterProgramHeaderTableEntry0 = positionAfterPMemsz + (uint64_t)8U;
                                    } else {
                                        positionAfterProgramHeaderTableEntry0 = EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterPMemsz);
                                    }
                                    uint64_t res;
                                    if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry0)) {
                                        res = positionAfterProgramHeaderTableEntry0;
                                    } else {
                                        Err("_PROGRAM_HEADER_TABLE_ENTRY",
                                            "P_ALIGN",
                                            EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry0),
                                            Ctxt,
                                            Input,
                                            positionAfterPMemsz);
                                        res = positionAfterProgramHeaderTableEntry0;
                                    }
                                    positionAfterProgramHeaderTableEntry = res;
                                }
                            }
                        }
                        if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry)) {
                            positionAfterProgramHeaderTableEntry0 = positionAfterProgramHeaderTableEntry;
                        } else {
                            Err("_PROGRAM_HEADER_TABLE_ENTRY",
                                "none",
                                EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry),
                                Ctxt,
                                Input,
                                positionAfterPPaddr);
                            positionAfterProgramHeaderTableEntry0 = positionAfterProgramHeaderTableEntry;
                        }
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterProgramHeaderTableEntry0)) {
        return positionAfterProgramHeaderTableEntry0;
    }
    Err("_PROGRAM_HEADER_TABLE_ENTRY",
        "none",
        EverParseErrorReasonOfResult(positionAfterProgramHeaderTableEntry0),
        Ctxt,
        Input,
        positionAfterPType);
    return positionAfterProgramHeaderTableEntry0;
}

static inline uint64_t
ValidateProgramHeaderTableOpt(
    uint16_t PhNum,
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLen,
    uint64_t StartPosition)
{
    if (PhNum == (uint16_t)(uint8_t)0U) {
        /* Validating field Empty */
        uint64_t positionAfterProgramHeaderTableOpt = StartPosition;
        if (EverParseIsSuccess(positionAfterProgramHeaderTableOpt)) {
            return positionAfterProgramHeaderTableOpt;
        }
        Err("_PROGRAM_HEADER_TABLE_OPT",
            "missing",
            EverParseErrorReasonOfResult(positionAfterProgramHeaderTableOpt),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterProgramHeaderTableOpt;
    }
    /* Validating field Tbl */
    BOOLEAN
    hasEnoughBytes = (uint64_t)((uint32_t)56U * (uint32_t)PhNum) <= (InputLen - StartPosition);
    uint64_t positionAfterProgramHeaderTableOpt;
    if (!hasEnoughBytes) {
        positionAfterProgramHeaderTableOpt =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    } else {
        uint8_t* truncatedInput = Input;
        uint64_t truncatedInputLength = StartPosition + (uint64_t)((uint32_t)56U * (uint32_t)PhNum);
        uint64_t result = StartPosition;
        while (TRUE) {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position))) {
                ite = TRUE;
            } else {
                uint64_t positionAfterProgramHeaderTableOpt = ValidateProgramHeaderTableEntry(
                    ElfFileSize, Ctxt, Err, truncatedInput, truncatedInputLength, position);
                uint64_t result1;
                if (EverParseIsSuccess(positionAfterProgramHeaderTableOpt)) {
                    result1 = positionAfterProgramHeaderTableOpt;
                } else {
                    Err("_PROGRAM_HEADER_TABLE_OPT",
                        ".element",
                        EverParseErrorReasonOfResult(positionAfterProgramHeaderTableOpt),
                        Ctxt,
                        truncatedInput,
                        position);
                    result1 = positionAfterProgramHeaderTableOpt;
                }
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite) {
                break;
            }
        }
        uint64_t res = result;
        positionAfterProgramHeaderTableOpt = res;
    }
    if (EverParseIsSuccess(positionAfterProgramHeaderTableOpt)) {
        return positionAfterProgramHeaderTableOpt;
    }
    Err("_PROGRAM_HEADER_TABLE_OPT",
        "missing",
        EverParseErrorReasonOfResult(positionAfterProgramHeaderTableOpt),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterProgramHeaderTableOpt;
}

static inline uint64_t
ValidateSectionHeaderTableEntry(
    uint16_t ShNum,
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    /* Validating field SH_NAME */
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes0 = (uint64_t)4U <= (InputLength - StartPosition);
    uint64_t positionAfterSectionHeaderTableEntry;
    if (hasBytes0) {
        positionAfterSectionHeaderTableEntry = StartPosition + (uint64_t)4U;
    } else {
        positionAfterSectionHeaderTableEntry =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry)) {
        res0 = positionAfterSectionHeaderTableEntry;
    } else {
        Err("_SECTION_HEADER_TABLE_ENTRY",
            "SH_NAME",
            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry),
            Ctxt,
            Input,
            StartPosition);
        res0 = positionAfterSectionHeaderTableEntry;
    }
    uint64_t positionAfterShName = res0;
    if (EverParseIsError(positionAfterShName)) {
        return positionAfterShName;
    }
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes1 = (uint64_t)4U <= (InputLength - positionAfterShName);
    uint64_t positionAfterSectionHeaderTableEntry0;
    if (hasBytes1) {
        positionAfterSectionHeaderTableEntry0 = positionAfterShName + (uint64_t)4U;
    } else {
        positionAfterSectionHeaderTableEntry0 =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShName);
    }
    uint64_t positionAfterShType;
    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry0)) {
        positionAfterShType = positionAfterSectionHeaderTableEntry0;
    } else {
        Err("_SECTION_HEADER_TABLE_ENTRY",
            "SH_TYPE",
            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry0),
            Ctxt,
            Input,
            positionAfterShName);
        positionAfterShType = positionAfterSectionHeaderTableEntry0;
    }
    if (EverParseIsError(positionAfterShType)) {
        return positionAfterShType;
    }
    uint32_t shType = Load32Le(Input + (uint32_t)positionAfterShName);
    /* Validating field SH_FLAGS */
    /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
    BOOLEAN hasBytes2 = (uint64_t)8U <= (InputLength - positionAfterShType);
    uint64_t positionAfterSectionHeaderTableEntry1;
    if (hasBytes2) {
        positionAfterSectionHeaderTableEntry1 = positionAfterShType + (uint64_t)8U;
    } else {
        positionAfterSectionHeaderTableEntry1 =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShType);
    }
    uint64_t res1;
    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry1)) {
        res1 = positionAfterSectionHeaderTableEntry1;
    } else {
        Err("_SECTION_HEADER_TABLE_ENTRY",
            "SH_FLAGS",
            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry1),
            Ctxt,
            Input,
            positionAfterShType);
        res1 = positionAfterSectionHeaderTableEntry1;
    }
    uint64_t positionAfterShFlags = res1;
    if (EverParseIsError(positionAfterShFlags)) {
        return positionAfterShFlags;
    }
    /* Validating field SH_ADDR */
    /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
    BOOLEAN hasBytes3 = (uint64_t)8U <= (InputLength - positionAfterShFlags);
    uint64_t positionAfterSectionHeaderTableEntry2;
    if (hasBytes3) {
        positionAfterSectionHeaderTableEntry2 = positionAfterShFlags + (uint64_t)8U;
    } else {
        positionAfterSectionHeaderTableEntry2 =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShFlags);
    }
    uint64_t res2;
    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry2)) {
        res2 = positionAfterSectionHeaderTableEntry2;
    } else {
        Err("_SECTION_HEADER_TABLE_ENTRY",
            "SH_ADDR",
            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry2),
            Ctxt,
            Input,
            positionAfterShFlags);
        res2 = positionAfterSectionHeaderTableEntry2;
    }
    uint64_t positionAfterShAddr = res2;
    if (EverParseIsError(positionAfterShAddr)) {
        return positionAfterShAddr;
    }
    /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
    BOOLEAN hasBytes4 = (uint64_t)8U <= (InputLength - positionAfterShAddr);
    uint64_t positionAfterSectionHeaderTableEntry3;
    if (hasBytes4) {
        positionAfterSectionHeaderTableEntry3 = positionAfterShAddr + (uint64_t)8U;
    } else {
        positionAfterSectionHeaderTableEntry3 =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShAddr);
    }
    uint64_t positionAfterShOffset;
    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry3)) {
        positionAfterShOffset = positionAfterSectionHeaderTableEntry3;
    } else {
        Err("_SECTION_HEADER_TABLE_ENTRY",
            "SH_OFFSET",
            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry3),
            Ctxt,
            Input,
            positionAfterShAddr);
        positionAfterShOffset = positionAfterSectionHeaderTableEntry3;
    }
    if (EverParseIsError(positionAfterShOffset)) {
        return positionAfterShOffset;
    }
    uint64_t shOffset = Load64Le(Input + (uint32_t)positionAfterShAddr);
    /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
    BOOLEAN hasBytes5 = (uint64_t)8U <= (InputLength - positionAfterShOffset);
    uint64_t positionAfternone;
    if (hasBytes5) {
        positionAfternone = positionAfterShOffset + (uint64_t)8U;
    } else {
        positionAfternone =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShOffset);
    }
    uint64_t positionAfterSectionHeaderTableEntry4;
    if (EverParseIsError(positionAfternone)) {
        positionAfterSectionHeaderTableEntry4 = positionAfternone;
    } else {
        uint64_t none = Load64Le(Input + (uint32_t)positionAfterShOffset);
        BOOLEAN
        noneConstraintIsOk =
            shType == (uint32_t)ELF____SH_NOBITS || (none <= ElfFileSize && shOffset <= (ElfFileSize - none));
        uint64_t positionAfternone1 = EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1)) {
            positionAfterSectionHeaderTableEntry4 = positionAfternone1;
        } else {
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes0 = (uint64_t)4U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0) {
                positionAfternone2 = positionAfternone1 + (uint64_t)4U;
            } else {
                positionAfternone2 =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
            }
            uint64_t positionAfterSectionHeaderTableEntry;
            if (EverParseIsError(positionAfternone2)) {
                positionAfterSectionHeaderTableEntry = positionAfternone2;
            } else {
                uint32_t none1 = Load32Le(Input + (uint32_t)positionAfternone1);
                BOOLEAN noneConstraintIsOk1 = none1 < (uint32_t)ShNum;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3)) {
                    positionAfterSectionHeaderTableEntry = positionAfternone3;
                } else {
                    /* Validating field SH_INFO */
                    /* Checking that we have enough space for a UINT32, i.e., 4
                     * bytes */
                    BOOLEAN hasBytes0 = (uint64_t)4U <= (InputLength - positionAfternone3);
                    uint64_t positionAfterSectionHeaderTableEntry0;
                    if (hasBytes0) {
                        positionAfterSectionHeaderTableEntry0 = positionAfternone3 + (uint64_t)4U;
                    } else {
                        positionAfterSectionHeaderTableEntry0 = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone3);
                    }
                    uint64_t res0;
                    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry0)) {
                        res0 = positionAfterSectionHeaderTableEntry0;
                    } else {
                        Err("_SECTION_HEADER_TABLE_ENTRY",
                            "SH_INFO",
                            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry0),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        res0 = positionAfterSectionHeaderTableEntry0;
                    }
                    uint64_t positionAfterShInfo = res0;
                    if (EverParseIsError(positionAfterShInfo)) {
                        positionAfterSectionHeaderTableEntry = positionAfterShInfo;
                    } else {
                        /* Validating field SH_ADDRALIGN */
                        /* Checking that we have enough space for a UINT64,
                         * i.e., 8 bytes */
                        BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfterShInfo);
                        uint64_t positionAfterSectionHeaderTableEntry0;
                        if (hasBytes0) {
                            positionAfterSectionHeaderTableEntry0 = positionAfterShInfo + (uint64_t)8U;
                        } else {
                            positionAfterSectionHeaderTableEntry0 = EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShInfo);
                        }
                        uint64_t res0;
                        if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry0)) {
                            res0 = positionAfterSectionHeaderTableEntry0;
                        } else {
                            Err("_SECTION_HEADER_TABLE_ENTRY",
                                "SH_ADDRALIGN",
                                EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry0),
                                Ctxt,
                                Input,
                                positionAfterShInfo);
                            res0 = positionAfterSectionHeaderTableEntry0;
                        }
                        uint64_t positionAfterShAddralign = res0;
                        if (EverParseIsError(positionAfterShAddralign)) {
                            positionAfterSectionHeaderTableEntry = positionAfterShAddralign;
                        } else {
                            /* Validating field SH_ENTSIZE */
                            /* Checking that we have enough space for a UINT64,
                             * i.e., 8 bytes */
                            BOOLEAN hasBytes = (uint64_t)8U <= (InputLength - positionAfterShAddralign);
                            uint64_t positionAfterSectionHeaderTableEntry0;
                            if (hasBytes) {
                                positionAfterSectionHeaderTableEntry0 = positionAfterShAddralign + (uint64_t)8U;
                            } else {
                                positionAfterSectionHeaderTableEntry0 = EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterShAddralign);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry0)) {
                                res = positionAfterSectionHeaderTableEntry0;
                            } else {
                                Err("_SECTION_HEADER_TABLE_ENTRY",
                                    "SH_ENTSIZE",
                                    EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry0),
                                    Ctxt,
                                    Input,
                                    positionAfterShAddralign);
                                res = positionAfterSectionHeaderTableEntry0;
                            }
                            positionAfterSectionHeaderTableEntry = res;
                        }
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry)) {
                positionAfterSectionHeaderTableEntry4 = positionAfterSectionHeaderTableEntry;
            } else {
                Err("_SECTION_HEADER_TABLE_ENTRY",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterSectionHeaderTableEntry4 = positionAfterSectionHeaderTableEntry;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterSectionHeaderTableEntry4)) {
        return positionAfterSectionHeaderTableEntry4;
    }
    Err("_SECTION_HEADER_TABLE_ENTRY",
        "none",
        EverParseErrorReasonOfResult(positionAfterSectionHeaderTableEntry4),
        Ctxt,
        Input,
        positionAfterShOffset);
    return positionAfterSectionHeaderTableEntry4;
}

static inline uint64_t
ValidateSectionHeaderTable(
    uint64_t PhTableEnd,
    uint64_t ShOff,
    uint16_t ShNum,
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterSectionHeaderTable;
    if (EverParseIsError(positionAfternone)) {
        positionAfterSectionHeaderTable = positionAfternone;
    } else {
        BOOLEAN
        noneConstraintIsOk = PhTableEnd <= ShOff && (ShOff - PhTableEnd) <= (uint64_t)ELF____MAX_UINT32;
        uint64_t positionAfternone1 = EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1)) {
            positionAfterSectionHeaderTable = positionAfternone1;
        } else {
            /* Validating field PHTABLE_SHTABLE_GAP */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(ShOff - PhTableEnd) <= (InputLength - positionAfternone1);
            uint64_t positionAfterSectionHeaderTable0;
            if (!hasEnoughBytes0) {
                positionAfterSectionHeaderTable0 =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
            } else {
                uint8_t* truncatedInput = Input;
                uint64_t truncatedInputLength = positionAfternone1 + (uint64_t)(uint32_t)(ShOff - PhTableEnd);
                uint64_t result = positionAfternone1;
                while (TRUE) {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position))) {
                        ite = TRUE;
                    } else {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes = (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterSectionHeaderTable;
                        if (hasBytes) {
                            positionAfterSectionHeaderTable = position + (uint64_t)1U;
                        } else {
                            positionAfterSectionHeaderTable =
                                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterSectionHeaderTable)) {
                            res = positionAfterSectionHeaderTable;
                        } else {
                            Err("_SECTION_HEADER_TABLE",
                                "PHTABLE_SHTABLE_GAP.element",
                                EverParseErrorReasonOfResult(positionAfterSectionHeaderTable),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterSectionHeaderTable;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite) {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterSectionHeaderTable0 = res;
            }
            uint64_t positionAfterPhtableShtableGap;
            if (EverParseIsSuccess(positionAfterSectionHeaderTable0)) {
                positionAfterPhtableShtableGap = positionAfterSectionHeaderTable0;
            } else {
                Err("_SECTION_HEADER_TABLE",
                    "PHTABLE_SHTABLE_GAP",
                    EverParseErrorReasonOfResult(positionAfterSectionHeaderTable0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterPhtableShtableGap = positionAfterSectionHeaderTable0;
            }
            if (EverParseIsError(positionAfterPhtableShtableGap)) {
                positionAfterSectionHeaderTable = positionAfterPhtableShtableGap;
            } else {
                /* Validating field SHTABLE */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)((uint32_t)64U * (uint32_t)ShNum) <= (InputLength - positionAfterPhtableShtableGap);
                uint64_t positionAfterSectionHeaderTable0;
                if (!hasEnoughBytes) {
                    positionAfterSectionHeaderTable0 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterPhtableShtableGap);
                } else {
                    uint8_t* truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterPhtableShtableGap + (uint64_t)((uint32_t)64U * (uint32_t)ShNum);
                    uint64_t result = positionAfterPhtableShtableGap;
                    while (TRUE) {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <= (truncatedInputLength - position))) {
                            ite = TRUE;
                        } else {
                            uint64_t positionAfterSectionHeaderTable = ValidateSectionHeaderTableEntry(
                                ShNum, ElfFileSize, Ctxt, Err, truncatedInput, truncatedInputLength, position);
                            uint64_t result1;
                            if (EverParseIsSuccess(positionAfterSectionHeaderTable)) {
                                result1 = positionAfterSectionHeaderTable;
                            } else {
                                Err("_SECTION_HEADER_TABLE",
                                    "SHTABLE.element",
                                    EverParseErrorReasonOfResult(positionAfterSectionHeaderTable),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                result1 = positionAfterSectionHeaderTable;
                            }
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite) {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterSectionHeaderTable0 = res;
                }
                uint64_t positionAfterSHTABLE;
                if (EverParseIsSuccess(positionAfterSectionHeaderTable0)) {
                    positionAfterSHTABLE = positionAfterSectionHeaderTable0;
                } else {
                    Err("_SECTION_HEADER_TABLE",
                        "SHTABLE",
                        EverParseErrorReasonOfResult(positionAfterSectionHeaderTable0),
                        Ctxt,
                        Input,
                        positionAfterPhtableShtableGap);
                    positionAfterSHTABLE = positionAfterSectionHeaderTable0;
                }
                if (EverParseIsError(positionAfterSHTABLE)) {
                    positionAfterSectionHeaderTable = positionAfterSHTABLE;
                } else {
                    /* ; Check that we have consumed all the bytes in the file;
                     */
                    uint64_t positionAfterSectionHeaderTable0 = positionAfterSHTABLE;
                    uint64_t positionAfterEndOfFile;
                    if (EverParseIsSuccess(positionAfterSectionHeaderTable0)) {
                        positionAfterEndOfFile = positionAfterSectionHeaderTable0;
                    } else {
                        Err("_SECTION_HEADER_TABLE",
                            "EndOfFile.base",
                            EverParseErrorReasonOfResult(positionAfterSectionHeaderTable0),
                            Ctxt,
                            Input,
                            positionAfterSHTABLE);
                        positionAfterEndOfFile = positionAfterSectionHeaderTable0;
                    }
                    uint64_t res;
                    if (EverParseIsSuccess(positionAfterEndOfFile)) {
                        uint32_t hd = (uint32_t)positionAfterSHTABLE;
                        BOOLEAN actionSuccessEndOfFile = (uint64_t)hd == ElfFileSize;
                        if (!actionSuccessEndOfFile) {
                            res = EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED;
                        } else {
                            res = positionAfterEndOfFile;
                        }
                    } else {
                        res = positionAfterEndOfFile;
                    }
                    uint64_t positionAfterSectionHeaderTable1 = res;
                    if (EverParseIsSuccess(positionAfterSectionHeaderTable1)) {
                        positionAfterSectionHeaderTable = positionAfterSectionHeaderTable1;
                    } else {
                        Err("_SECTION_HEADER_TABLE",
                            "EndOfFile",
                            EverParseErrorReasonOfResult(positionAfterSectionHeaderTable1),
                            Ctxt,
                            Input,
                            positionAfterSHTABLE);
                        positionAfterSectionHeaderTable = positionAfterSectionHeaderTable1;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterSectionHeaderTable)) {
        return positionAfterSectionHeaderTable;
    }
    Err("_SECTION_HEADER_TABLE",
        "none",
        EverParseErrorReasonOfResult(positionAfterSectionHeaderTable),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterSectionHeaderTable;
}

static inline uint64_t
ValidateNoSectionHeaderTable(
    uint64_t PhTableEnd,
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterNoSectionHeaderTable;
    if (EverParseIsError(positionAfternone)) {
        positionAfterNoSectionHeaderTable = positionAfternone;
    } else {
        BOOLEAN
        noneConstraintIsOk = PhTableEnd <= ElfFileSize && (ElfFileSize - PhTableEnd) <= (uint64_t)ELF____MAX_UINT32;
        uint64_t positionAfternone1 = EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1)) {
            positionAfterNoSectionHeaderTable = positionAfternone1;
        } else {
            /* Validating field Rest */
            BOOLEAN
            hasEnoughBytes = (uint64_t)(uint32_t)(ElfFileSize - PhTableEnd) <= (InputLength - positionAfternone1);
            uint64_t positionAfterNoSectionHeaderTable0;
            if (!hasEnoughBytes) {
                positionAfterNoSectionHeaderTable0 =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
            } else {
                uint8_t* truncatedInput = Input;
                uint64_t truncatedInputLength = positionAfternone1 + (uint64_t)(uint32_t)(ElfFileSize - PhTableEnd);
                uint64_t result = positionAfternone1;
                while (TRUE) {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position))) {
                        ite = TRUE;
                    } else {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes = (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterNoSectionHeaderTable;
                        if (hasBytes) {
                            positionAfterNoSectionHeaderTable = position + (uint64_t)1U;
                        } else {
                            positionAfterNoSectionHeaderTable =
                                EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterNoSectionHeaderTable)) {
                            res = positionAfterNoSectionHeaderTable;
                        } else {
                            Err("_NO_SECTION_HEADER_TABLE",
                                "Rest.element",
                                EverParseErrorReasonOfResult(positionAfterNoSectionHeaderTable),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterNoSectionHeaderTable;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite) {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterNoSectionHeaderTable0 = res;
            }
            if (EverParseIsSuccess(positionAfterNoSectionHeaderTable0)) {
                positionAfterNoSectionHeaderTable = positionAfterNoSectionHeaderTable0;
            } else {
                Err("_NO_SECTION_HEADER_TABLE",
                    "Rest",
                    EverParseErrorReasonOfResult(positionAfterNoSectionHeaderTable0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterNoSectionHeaderTable = positionAfterNoSectionHeaderTable0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterNoSectionHeaderTable)) {
        return positionAfterNoSectionHeaderTable;
    }
    Err("_NO_SECTION_HEADER_TABLE",
        "none",
        EverParseErrorReasonOfResult(positionAfterNoSectionHeaderTable),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterNoSectionHeaderTable;
}

static inline uint64_t
ValidateSectionHeaderTableOpt(
    uint64_t PhTableEnd,
    uint64_t ShOff,
    uint16_t ShNum,
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLen,
    uint64_t StartPosition)
{
    if (ShNum == (uint16_t)(uint8_t)0U) {
        /* ; When there is no Section Header table,; the following type ensures
         * that there are at least ElfFileSize - PhTableEnd; bytes remaining in
         * the file; */
        uint64_t positionAfterSectionHeaderTableOpt =
            ValidateNoSectionHeaderTable(PhTableEnd, ElfFileSize, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterSectionHeaderTableOpt)) {
            return positionAfterSectionHeaderTableOpt;
        }
        Err("_SECTION_HEADER_TABLE_OPT",
            "missing",
            EverParseErrorReasonOfResult(positionAfterSectionHeaderTableOpt),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterSectionHeaderTableOpt;
    }
    /* Validating field Tbl */
    uint64_t positionAfterSectionHeaderTableOpt =
        ValidateSectionHeaderTable(PhTableEnd, ShOff, ShNum, ElfFileSize, Ctxt, Err, Input, InputLen, StartPosition);
    if (EverParseIsSuccess(positionAfterSectionHeaderTableOpt)) {
        return positionAfterSectionHeaderTableOpt;
    }
    Err("_SECTION_HEADER_TABLE_OPT",
        "missing",
        EverParseErrorReasonOfResult(positionAfterSectionHeaderTableOpt),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterSectionHeaderTableOpt;
}

uint64_t
ElfValidateElf(
    uint64_t ElfFileSize,
    uint8_t* Ctxt,
    void (*Err)(EverParseString x0, EverParseString x1, EverParseString x2, uint8_t* x3, uint8_t* x4, uint64_t x5),
    uint8_t* Input,
    uint64_t InputLength,
    uint64_t StartPosition)
{
    /* ELF HEADER BEGIN */
    uint64_t positionAfterElf = ValidateEIdent(Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterIDENT;
    if (EverParseIsSuccess(positionAfterElf)) {
        positionAfterIDENT = positionAfterElf;
    } else {
        Err("_ELF", "IDENT", EverParseErrorReasonOfResult(positionAfterElf), Ctxt, Input, StartPosition);
        positionAfterIDENT = positionAfterElf;
    }
    if (EverParseIsError(positionAfterIDENT)) {
        return positionAfterIDENT;
    }
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes0 = (uint64_t)2U <= (InputLength - positionAfterIDENT);
    uint64_t positionAfternone;
    if (hasBytes0) {
        positionAfternone = positionAfterIDENT + (uint64_t)2U;
    } else {
        positionAfternone =
            EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterIDENT);
    }
    uint64_t positionAfterElf0;
    if (EverParseIsError(positionAfternone)) {
        positionAfterElf0 = positionAfternone;
    } else {
        uint16_t r0 = Load16Le(Input + (uint32_t)positionAfterIDENT);
        uint16_t none = (uint16_t)(uint32_t)r0;
        BOOLEAN
        noneConstraintIsOk =
            none != ELF____ET_NONE && (ELF____ET_NONE == none || ELF____ET_REL == none || ELF____ET_EXEC == none ||
                                       ELF____ET_DYN == none || ELF____ET_CORE == none);
        uint64_t positionAfternone1 = EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1)) {
            positionAfterElf0 = positionAfternone1;
        } else {
            /* ; We can restrict the values of E_MACHINE by making its type an
             * enum, for example; The elf man page lists some possible values,
             * but that list does not seem to be exhaustive; */
            /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
            BOOLEAN hasBytes0 = (uint64_t)2U <= (InputLength - positionAfternone1);
            uint64_t positionAfterElf;
            if (hasBytes0) {
                positionAfterElf = positionAfternone1 + (uint64_t)2U;
            } else {
                positionAfterElf =
                    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
            }
            uint64_t res0;
            if (EverParseIsSuccess(positionAfterElf)) {
                res0 = positionAfterElf;
            } else {
                Err("_ELF",
                    "E_MACHINE",
                    EverParseErrorReasonOfResult(positionAfterElf),
                    Ctxt,
                    Input,
                    positionAfternone1);
                res0 = positionAfterElf;
            }
            uint64_t positionAfterEMachine = res0;
            if (EverParseIsError(positionAfterEMachine)) {
                positionAfterElf0 = positionAfterEMachine;
            } else {
                /* Checking that we have enough space for a UINT32, i.e., 4
                 * bytes */
                BOOLEAN hasBytes0 = (uint64_t)4U <= (InputLength - positionAfterEMachine);
                uint64_t positionAfternone2;
                if (hasBytes0) {
                    positionAfternone2 = positionAfterEMachine + (uint64_t)4U;
                } else {
                    positionAfternone2 =
                        EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterEMachine);
                }
                uint64_t positionAfterElf;
                if (EverParseIsError(positionAfternone2)) {
                    positionAfterElf = positionAfternone2;
                } else {
                    uint32_t none1 = Load32Le(Input + (uint32_t)positionAfterEMachine);
                    BOOLEAN noneConstraintIsOk1 = none1 == (uint32_t)(uint8_t)1U;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3)) {
                        positionAfterElf = positionAfternone3;
                    } else {
                        /* Validating field E_ENTRY */
                        /* Checking that we have enough space for a UINT64,
                         * i.e., 8 bytes */
                        BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfternone3);
                        uint64_t positionAfterElf0;
                        if (hasBytes0) {
                            positionAfterElf0 = positionAfternone3 + (uint64_t)8U;
                        } else {
                            positionAfterElf0 = EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone3);
                        }
                        uint64_t res0;
                        if (EverParseIsSuccess(positionAfterElf0)) {
                            res0 = positionAfterElf0;
                        } else {
                            Err("_ELF",
                                "E_ENTRY",
                                EverParseErrorReasonOfResult(positionAfterElf0),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            res0 = positionAfterElf0;
                        }
                        uint64_t positionAfterEEntry = res0;
                        if (EverParseIsError(positionAfterEEntry)) {
                            positionAfterElf = positionAfterEEntry;
                        } else {
                            /* Checking that we have enough space for a UINT64,
                             * i.e., 8 bytes */
                            BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfterEEntry);
                            uint64_t positionAfterElf0;
                            if (hasBytes0) {
                                positionAfterElf0 = positionAfterEEntry + (uint64_t)8U;
                            } else {
                                positionAfterElf0 = EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterEEntry);
                            }
                            uint64_t positionAfterEPhoff;
                            if (EverParseIsSuccess(positionAfterElf0)) {
                                positionAfterEPhoff = positionAfterElf0;
                            } else {
                                Err("_ELF",
                                    "E_PHOFF",
                                    EverParseErrorReasonOfResult(positionAfterElf0),
                                    Ctxt,
                                    Input,
                                    positionAfterEEntry);
                                positionAfterEPhoff = positionAfterElf0;
                            }
                            if (EverParseIsError(positionAfterEPhoff)) {
                                positionAfterElf = positionAfterEPhoff;
                            } else {
                                uint64_t ePhoff = Load64Le(Input + (uint32_t)positionAfterEEntry);
                                /* Checking that we have enough space for a
                                 * UINT64, i.e., 8 bytes */
                                BOOLEAN hasBytes0 = (uint64_t)8U <= (InputLength - positionAfterEPhoff);
                                uint64_t positionAfterElf0;
                                if (hasBytes0) {
                                    positionAfterElf0 = positionAfterEPhoff + (uint64_t)8U;
                                } else {
                                    positionAfterElf0 = EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterEPhoff);
                                }
                                uint64_t positionAfterEShoff;
                                if (EverParseIsSuccess(positionAfterElf0)) {
                                    positionAfterEShoff = positionAfterElf0;
                                } else {
                                    Err("_ELF",
                                        "E_SHOFF",
                                        EverParseErrorReasonOfResult(positionAfterElf0),
                                        Ctxt,
                                        Input,
                                        positionAfterEPhoff);
                                    positionAfterEShoff = positionAfterElf0;
                                }
                                if (EverParseIsError(positionAfterEShoff)) {
                                    positionAfterElf = positionAfterEShoff;
                                } else {
                                    uint64_t eShoff = Load64Le(Input + (uint32_t)positionAfterEPhoff);
                                    /* Validating field E_FLAGS */
                                    /* Checking that we have enough space for a
                                     * UINT32, i.e., 4 bytes */
                                    BOOLEAN hasBytes0 = (uint64_t)4U <= (InputLength - positionAfterEShoff);
                                    uint64_t positionAfterElf0;
                                    if (hasBytes0) {
                                        positionAfterElf0 = positionAfterEShoff + (uint64_t)4U;
                                    } else {
                                        positionAfterElf0 = EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterEShoff);
                                    }
                                    uint64_t res;
                                    if (EverParseIsSuccess(positionAfterElf0)) {
                                        res = positionAfterElf0;
                                    } else {
                                        Err("_ELF",
                                            "E_FLAGS",
                                            EverParseErrorReasonOfResult(positionAfterElf0),
                                            Ctxt,
                                            Input,
                                            positionAfterEShoff);
                                        res = positionAfterElf0;
                                    }
                                    uint64_t positionAfterEFlags = res;
                                    if (EverParseIsError(positionAfterEFlags)) {
                                        positionAfterElf = positionAfterEFlags;
                                    } else {
                                        /* Checking that we have enough space
                                         * for a UINT16, i.e., 2 bytes */
                                        BOOLEAN hasBytes0 = (uint64_t)2U <= (InputLength - positionAfterEFlags);
                                        uint64_t positionAfternone4;
                                        if (hasBytes0) {
                                            positionAfternone4 = positionAfterEFlags + (uint64_t)2U;
                                        } else {
                                            positionAfternone4 = EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterEFlags);
                                        }
                                        uint64_t positionAfterElf0;
                                        if (EverParseIsError(positionAfternone4)) {
                                            positionAfterElf0 = positionAfternone4;
                                        } else {
                                            uint16_t r0 = Load16Le(Input + (uint32_t)positionAfterEFlags);
                                            uint16_t none2 = (uint16_t)(uint32_t)r0;
                                            BOOLEAN noneConstraintIsOk2 = (uint32_t)none2 == (uint32_t)64U;
                                            uint64_t positionAfternone5 =
                                                EverParseCheckConstraintOk(noneConstraintIsOk2, positionAfternone4);
                                            if (EverParseIsError(positionAfternone5)) {
                                                positionAfterElf0 = positionAfternone5;
                                            } else {
                                                /* Checking that we have enough
                                                 * space for a UINT16, i.e., 2
                                                 * bytes */
                                                BOOLEAN hasBytes0 = (uint64_t)2U <= (InputLength - positionAfternone5);
                                                uint64_t positionAfterElf;
                                                if (hasBytes0) {
                                                    positionAfterElf = positionAfternone5 + (uint64_t)2U;
                                                } else {
                                                    positionAfterElf = EverParseSetValidatorErrorPos(
                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone5);
                                                }
                                                uint64_t positionAfterEPhentsize;
                                                if (EverParseIsSuccess(positionAfterElf)) {
                                                    positionAfterEPhentsize = positionAfterElf;
                                                } else {
                                                    Err("_ELF",
                                                        "E_PHENTSIZE",
                                                        EverParseErrorReasonOfResult(positionAfterElf),
                                                        Ctxt,
                                                        Input,
                                                        positionAfternone5);
                                                    positionAfterEPhentsize = positionAfterElf;
                                                }
                                                if (EverParseIsError(positionAfterEPhentsize)) {
                                                    positionAfterElf0 = positionAfterEPhentsize;
                                                } else {
                                                    uint16_t r0 = Load16Le(Input + (uint32_t)positionAfternone5);
                                                    uint16_t ePhentsize = (uint16_t)(uint32_t)r0;
                                                    /* Checking that we have
                                                     * enough space for a
                                                     * UINT16, i.e., 2 bytes */
                                                    BOOLEAN
                                                    hasBytes0 = (uint64_t)2U <= (InputLength - positionAfterEPhentsize);
                                                    uint64_t positionAfternone6;
                                                    if (hasBytes0) {
                                                        positionAfternone6 = positionAfterEPhentsize + (uint64_t)2U;
                                                    } else {
                                                        positionAfternone6 = EverParseSetValidatorErrorPos(
                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                            positionAfterEPhentsize);
                                                    }
                                                    uint64_t positionAfterElf;
                                                    if (EverParseIsError(positionAfternone6)) {
                                                        positionAfterElf = positionAfternone6;
                                                    } else {
                                                        uint16_t r0 =
                                                            Load16Le(Input + (uint32_t)positionAfterEPhentsize);
                                                        uint16_t none3 = (uint16_t)(uint32_t)r0;
                                                        BOOLEAN
                                                        noneConstraintIsOk3 =
                                                            (none3 == (uint16_t)(uint8_t)0U &&
                                                             ePhoff == (uint64_t)(uint8_t)0U) ||
                                                            ((uint16_t)(uint8_t)0U < none3 && none3 < ELF____PN_XNUM &&
                                                             (uint64_t)(uint32_t)64U == ePhoff &&
                                                             (uint32_t)ePhentsize == (uint32_t)56U);
                                                        uint64_t positionAfternone7 = EverParseCheckConstraintOk(
                                                            noneConstraintIsOk3, positionAfternone6);
                                                        if (EverParseIsError(positionAfternone7)) {
                                                            positionAfterElf = positionAfternone7;
                                                        } else {
                                                            /* Checking that we
                                                             * have enough space
                                                             * for a UINT16,
                                                             * i.e., 2 bytes */
                                                            BOOLEAN
                                                            hasBytes0 =
                                                                (uint64_t)2U <= (InputLength - positionAfternone7);
                                                            uint64_t positionAfterElf0;
                                                            if (hasBytes0) {
                                                                positionAfterElf0 = positionAfternone7 + (uint64_t)2U;
                                                            } else {
                                                                positionAfterElf0 = EverParseSetValidatorErrorPos(
                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    positionAfternone7);
                                                            }
                                                            uint64_t positionAfterEShentsize;
                                                            if (EverParseIsSuccess(positionAfterElf0)) {
                                                                positionAfterEShentsize = positionAfterElf0;
                                                            } else {
                                                                Err("_ELF",
                                                                    "E_"
                                                                    "SHENTSIZE",
                                                                    EverParseErrorReasonOfResult(positionAfterElf0),
                                                                    Ctxt,
                                                                    Input,
                                                                    positionAfternone7);
                                                                positionAfterEShentsize = positionAfterElf0;
                                                            }
                                                            if (EverParseIsError(positionAfterEShentsize)) {
                                                                positionAfterElf = positionAfterEShentsize;
                                                            } else {
                                                                uint16_t r0 =
                                                                    Load16Le(Input + (uint32_t)positionAfternone7);
                                                                uint16_t eShentsize = (uint16_t)(uint32_t)r0;
                                                                /* Checking that
                                                                 * we have
                                                                 * enough space
                                                                 * for a UINT16,
                                                                 * i.e., 2 bytes
                                                                 */
                                                                BOOLEAN
                                                                hasBytes0 = (uint64_t)2U <=
                                                                            (InputLength - positionAfterEShentsize);
                                                                uint64_t positionAfternone8;
                                                                if (hasBytes0) {
                                                                    positionAfternone8 =
                                                                        positionAfterEShentsize + (uint64_t)2U;
                                                                } else {
                                                                    positionAfternone8 = EverParseSetValidatorErrorPos(
                                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                        positionAfterEShentsize);
                                                                }
                                                                uint64_t positionAfterElf0;
                                                                if (EverParseIsError(positionAfternone8)) {
                                                                    positionAfterElf0 = positionAfternone8;
                                                                } else {
                                                                    uint16_t r0 = Load16Le(
                                                                        Input + (uint32_t)positionAfterEShentsize);
                                                                    uint16_t none4 = (uint16_t)(uint32_t)r0;
                                                                    BOOLEAN
                                                                    noneConstraintIsOk4 =
                                                                        (none4 == (uint16_t)(uint8_t)0U &&
                                                                         eShoff == (uint64_t)(uint8_t)0U) ||
                                                                        ((uint16_t)(uint8_t)0U < none4 &&
                                                                         none4 < ELF____SHN_LORESERVE &&
                                                                         (uint32_t)eShentsize == (uint32_t)64U);
                                                                    uint64_t positionAfternone9 =
                                                                        EverParseCheckConstraintOk(
                                                                            noneConstraintIsOk4, positionAfternone8);
                                                                    if (EverParseIsError(positionAfternone9)) {
                                                                        positionAfterElf0 = positionAfternone9;
                                                                    } else {
                                                                        /* Checking
                                                                         * that
                                                                         * we
                                                                         * have
                                                                         * enough
                                                                         * space
                                                                         * for a
                                                                         * UINT16,
                                                                         * i.e.,
                                                                         * 2
                                                                         * bytes
                                                                         */
                                                                        BOOLEAN
                                                                        hasBytes = (uint64_t)2U <=
                                                                                   (InputLength - positionAfternone9);
                                                                        uint64_t positionAfternone10;
                                                                        if (hasBytes) {
                                                                            positionAfternone10 =
                                                                                positionAfternone9 + (uint64_t)2U;
                                                                        } else {
                                                                            positionAfternone10 =
                                                                                EverParseSetValidatorErrorPos(
                                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                    positionAfternone9);
                                                                        }
                                                                        uint64_t positionAfterElf;
                                                                        if (EverParseIsError(positionAfternone10)) {
                                                                            positionAfterElf = positionAfternone10;
                                                                        } else {
                                                                            uint16_t r = Load16Le(
                                                                                Input + (uint32_t)positionAfternone9);
                                                                            uint16_t none5 = (uint16_t)(uint32_t)r;
                                                                            BOOLEAN
                                                                            noneConstraintIsOk5 =
                                                                                (none4 == (uint16_t)(uint8_t)0U &&
                                                                                 none5 == (uint16_t)ELF____SHN_UNDEF) ||
                                                                                ((uint16_t)(uint8_t)0U < none4 &&
                                                                                 none5 < none4);
                                                                            uint64_t positionAfternone11 =
                                                                                EverParseCheckConstraintOk(
                                                                                    noneConstraintIsOk5,
                                                                                    positionAfternone10);
                                                                            if (EverParseIsError(positionAfternone11)) {
                                                                                positionAfterElf = positionAfternone11;
                                                                            } else {
                                                                                /* ELF HEADER END; (Optional) Program
                                                                                 * Header table */
                                                                                uint64_t positionAfterElf0 =
                                                                                    ValidateProgramHeaderTableOpt(
                                                                                        none3,
                                                                                        ElfFileSize,
                                                                                        Ctxt,
                                                                                        Err,
                                                                                        Input,
                                                                                        InputLength,
                                                                                        positionAfternone11);
                                                                                uint64_t positionAfterPhTable;
                                                                                if (EverParseIsSuccess(
                                                                                        positionAfterElf0)) {
                                                                                    positionAfterPhTable =
                                                                                        positionAfterElf0;
                                                                                } else {
                                                                                    Err("_ELF",
                                                                                        "PH_TABLE",
                                                                                        EverParseErrorReasonOfResult(
                                                                                            positionAfterElf0),
                                                                                        Ctxt,
                                                                                        Input,
                                                                                        positionAfternone11);
                                                                                    positionAfterPhTable =
                                                                                        positionAfterElf0;
                                                                                }
                                                                                if (EverParseIsError(
                                                                                        positionAfterPhTable)) {
                                                                                    positionAfterElf =
                                                                                        positionAfterPhTable;
                                                                                } else {
                                                                                    /* (Optional) Section Header Table
                                                                                     */
                                                                                    uint64_t ite;
                                                                                    if (none3 ==
                                                                                        (uint16_t)(uint8_t)0U) {
                                                                                        ite = (uint64_t)none2;
                                                                                    } else {
                                                                                        ite = ePhoff;
                                                                                    }
                                                                                    uint64_t positionAfterElf0 =
                                                                                        ValidateSectionHeaderTableOpt(
                                                                                            ite +
                                                                                                (uint64_t)((uint32_t)56U * (uint32_t)none3),
                                                                                            eShoff,
                                                                                            none4,
                                                                                            ElfFileSize,
                                                                                            Ctxt,
                                                                                            Err,
                                                                                            Input,
                                                                                            InputLength,
                                                                                            positionAfterPhTable);
                                                                                    if (EverParseIsSuccess(
                                                                                            positionAfterElf0)) {
                                                                                        positionAfterElf =
                                                                                            positionAfterElf0;
                                                                                    } else {
                                                                                        Err("_ELF",
                                                                                            "SH_TABLE",
                                                                                            EverParseErrorReasonOfResult(
                                                                                                positionAfterElf0),
                                                                                            Ctxt,
                                                                                            Input,
                                                                                            positionAfterPhTable);
                                                                                        positionAfterElf =
                                                                                            positionAfterElf0;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        if (EverParseIsSuccess(positionAfterElf)) {
                                                                            positionAfterElf0 = positionAfterElf;
                                                                        } else {
                                                                            Err("_ELF",
                                                                                "none",
                                                                                EverParseErrorReasonOfResult(
                                                                                    positionAfterElf),
                                                                                Ctxt,
                                                                                Input,
                                                                                positionAfternone9);
                                                                            positionAfterElf0 = positionAfterElf;
                                                                        }
                                                                    }
                                                                }
                                                                if (EverParseIsSuccess(positionAfterElf0)) {
                                                                    positionAfterElf = positionAfterElf0;
                                                                } else {
                                                                    Err("_ELF",
                                                                        "none",
                                                                        EverParseErrorReasonOfResult(positionAfterElf0),
                                                                        Ctxt,
                                                                        Input,
                                                                        positionAfterEShentsize);
                                                                    positionAfterElf = positionAfterElf0;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if (EverParseIsSuccess(positionAfterElf)) {
                                                        positionAfterElf0 = positionAfterElf;
                                                    } else {
                                                        Err("_ELF",
                                                            "none",
                                                            EverParseErrorReasonOfResult(positionAfterElf),
                                                            Ctxt,
                                                            Input,
                                                            positionAfterEPhentsize);
                                                        positionAfterElf0 = positionAfterElf;
                                                    }
                                                }
                                            }
                                        }
                                        if (EverParseIsSuccess(positionAfterElf0)) {
                                            positionAfterElf = positionAfterElf0;
                                        } else {
                                            Err("_ELF",
                                                "none",
                                                EverParseErrorReasonOfResult(positionAfterElf0),
                                                Ctxt,
                                                Input,
                                                positionAfterEFlags);
                                            positionAfterElf = positionAfterElf0;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterElf)) {
                    positionAfterElf0 = positionAfterElf;
                } else {
                    Err("_ELF",
                        "none",
                        EverParseErrorReasonOfResult(positionAfterElf),
                        Ctxt,
                        Input,
                        positionAfterEMachine);
                    positionAfterElf0 = positionAfterElf;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterElf0)) {
        return positionAfterElf0;
    }
    Err("_ELF", "none", EverParseErrorReasonOfResult(positionAfterElf0), Ctxt, Input, positionAfterIDENT);
    return positionAfterElf0;
}
