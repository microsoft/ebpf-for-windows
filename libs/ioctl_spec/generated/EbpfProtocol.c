

#include "EbpfProtocol.h"

static inline uint64_t
ValidateCreateProgramBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterCreateProgramBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterCreateProgramBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____CREATE_PROGRAM_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterCreateProgramBody = positionAfternone1;
        }
        else
        {
            /* Validating field ProgramType */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)16U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterCreateProgramBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterCreateProgramBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)16U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterCreateProgramBody;
                        if (hasBytes)
                        {
                            positionAfterCreateProgramBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterCreateProgramBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterCreateProgramBody))
                        {
                            res = positionAfterCreateProgramBody;
                        }
                        else
                        {
                            Err("_CREATE_PROGRAM_BODY",
                                "ProgramType.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterCreateProgramBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterCreateProgramBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterCreateProgramBody0 = res;
            }
            uint64_t positionAfterProgramType;
            if (EverParseIsSuccess(positionAfterCreateProgramBody0))
            {
                positionAfterProgramType = positionAfterCreateProgramBody0;
            }
            else
            {
                Err("_CREATE_PROGRAM_BODY",
                    "ProgramType",
                    EverParseErrorReasonOfResult(
                        positionAfterCreateProgramBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterProgramType = positionAfterCreateProgramBody0;
            }
            if (EverParseIsError(positionAfterProgramType))
            {
                positionAfterCreateProgramBody = positionAfterProgramType;
            }
            else
            {
                /* Checking that we have enough space for a UINT16, i.e., 2
                 * bytes */
                BOOLEAN hasBytes0 =
                    (uint64_t)2U <= (InputLength - positionAfterProgramType);
                uint64_t positionAfternone2;
                if (hasBytes0)
                {
                    positionAfternone2 =
                        positionAfterProgramType + (uint64_t)2U;
                }
                else
                {
                    positionAfternone2 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterProgramType);
                }
                uint64_t positionAfterCreateProgramBody0;
                if (EverParseIsError(positionAfternone2))
                {
                    positionAfterCreateProgramBody0 = positionAfternone2;
                }
                else
                {
                    uint16_t r0 =
                        Load16Le(Input + (uint32_t)positionAfterProgramType);
                    uint16_t none1 = (uint16_t)(uint32_t)r0;
                    BOOLEAN
                    noneConstraintIsOk1 =
                        none1 >=
                            (uint16_t)
                                EBPFPROTOCOL____CREATE_PROGRAM_DATA_OFFSET &&
                        none1 <= MessageLength;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                        noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3))
                    {
                        positionAfterCreateProgramBody0 = positionAfternone3;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT16,
                         * i.e., 2 bytes */
                        BOOLEAN hasBytes0 =
                            (uint64_t)2U <= (InputLength - positionAfternone3);
                        uint64_t positionAfternone4;
                        if (hasBytes0)
                        {
                            positionAfternone4 =
                                positionAfternone3 + (uint64_t)2U;
                        }
                        else
                        {
                            positionAfternone4 = EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfternone3);
                        }
                        uint64_t positionAfterCreateProgramBody;
                        if (EverParseIsError(positionAfternone4))
                        {
                            positionAfterCreateProgramBody = positionAfternone4;
                        }
                        else
                        {
                            uint16_t r =
                                Load16Le(Input + (uint32_t)positionAfternone3);
                            uint16_t none2 = (uint16_t)(uint32_t)r;
                            BOOLEAN noneConstraintIsOk2 =
                                none2 >= none1 && none2 <= MessageLength;
                            uint64_t positionAfternone5 =
                                EverParseCheckConstraintOk(
                                    noneConstraintIsOk2, positionAfternone4);
                            if (EverParseIsError(positionAfternone5))
                            {
                                positionAfterCreateProgramBody =
                                    positionAfternone5;
                            }
                            else
                            {
                                /* Validating field Data */
                                BOOLEAN
                                hasEnoughBytes =
                                    (uint64_t)(uint32_t)(
                                        MessageLength -
                                        (uint16_t)
                                            EBPFPROTOCOL____CREATE_PROGRAM_DATA_OFFSET) <=
                                    (InputLength - positionAfternone5);
                                uint64_t positionAfterCreateProgramBody0;
                                if (!hasEnoughBytes)
                                {
                                    positionAfterCreateProgramBody0 =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            positionAfternone5);
                                }
                                else
                                {
                                    uint8_t *truncatedInput = Input;
                                    uint64_t truncatedInputLength =
                                        positionAfternone5 +
                                        (uint64_t)(uint32_t)(
                                            MessageLength -
                                            (uint16_t)
                                                EBPFPROTOCOL____CREATE_PROGRAM_DATA_OFFSET);
                                    uint64_t result = positionAfternone5;
                                    while (TRUE)
                                    {
                                        uint64_t position = *&result;
                                        BOOLEAN ite;
                                        if (!((uint64_t)1U <=
                                              (truncatedInputLength -
                                               position)))
                                        {
                                            ite = TRUE;
                                        }
                                        else
                                        {
                                            /* Checking that we have enough
                                             * space for a UINT8, i.e., 1 byte
                                             */
                                            BOOLEAN hasBytes =
                                                (uint64_t)1U <=
                                                (truncatedInputLength -
                                                 position);
                                            uint64_t
                                                positionAfterCreateProgramBody;
                                            if (hasBytes)
                                            {
                                                positionAfterCreateProgramBody =
                                                    position + (uint64_t)1U;
                                            }
                                            else
                                            {
                                                positionAfterCreateProgramBody =
                                                    EverParseSetValidatorErrorPos(
                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                        position);
                                            }
                                            uint64_t res;
                                            if (EverParseIsSuccess(
                                                    positionAfterCreateProgramBody))
                                            {
                                                res =
                                                    positionAfterCreateProgramBody;
                                            }
                                            else
                                            {
                                                Err("_CREATE_PROGRAM_BODY",
                                                    "Data.element",
                                                    EverParseErrorReasonOfResult(
                                                        positionAfterCreateProgramBody),
                                                    Ctxt,
                                                    truncatedInput,
                                                    position);
                                                res =
                                                    positionAfterCreateProgramBody;
                                            }
                                            uint64_t result1 = res;
                                            result = result1;
                                            ite = EverParseIsError(result1);
                                        }
                                        if (ite)
                                        {
                                            break;
                                        }
                                    }
                                    uint64_t res = result;
                                    positionAfterCreateProgramBody0 = res;
                                }
                                if (EverParseIsSuccess(
                                        positionAfterCreateProgramBody0))
                                {
                                    positionAfterCreateProgramBody =
                                        positionAfterCreateProgramBody0;
                                }
                                else
                                {
                                    Err("_CREATE_PROGRAM_BODY",
                                        "Data",
                                        EverParseErrorReasonOfResult(
                                            positionAfterCreateProgramBody0),
                                        Ctxt,
                                        Input,
                                        positionAfternone5);
                                    positionAfterCreateProgramBody =
                                        positionAfterCreateProgramBody0;
                                }
                            }
                        }
                        if (EverParseIsSuccess(positionAfterCreateProgramBody))
                        {
                            positionAfterCreateProgramBody0 =
                                positionAfterCreateProgramBody;
                        }
                        else
                        {
                            Err("_CREATE_PROGRAM_BODY",
                                "none",
                                EverParseErrorReasonOfResult(
                                    positionAfterCreateProgramBody),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            positionAfterCreateProgramBody0 =
                                positionAfterCreateProgramBody;
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterCreateProgramBody0))
                {
                    positionAfterCreateProgramBody =
                        positionAfterCreateProgramBody0;
                }
                else
                {
                    Err("_CREATE_PROGRAM_BODY",
                        "none",
                        EverParseErrorReasonOfResult(
                            positionAfterCreateProgramBody0),
                        Ctxt,
                        Input,
                        positionAfterProgramType);
                    positionAfterCreateProgramBody =
                        positionAfterCreateProgramBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterCreateProgramBody))
    {
        return positionAfterCreateProgramBody;
    }
    Err("_CREATE_PROGRAM_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterCreateProgramBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterCreateProgramBody;
}

static inline uint64_t
ValidateCreateMapBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterCreateMapBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterCreateMapBody = positionAfternone;
    }
    else
    {
        BOOLEAN noneConstraintIsOk =
            MessageLength >= (uint16_t)EBPFPROTOCOL____CREATE_MAP_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterCreateMapBody = positionAfternone1;
        }
        else
        {
            /* Validating field MapDefinition */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)24U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterCreateMapBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterCreateMapBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)24U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterCreateMapBody;
                        if (hasBytes)
                        {
                            positionAfterCreateMapBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterCreateMapBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterCreateMapBody))
                        {
                            res = positionAfterCreateMapBody;
                        }
                        else
                        {
                            Err("_CREATE_MAP_BODY",
                                "MapDefinition.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterCreateMapBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterCreateMapBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterCreateMapBody0 = res;
            }
            uint64_t positionAfterMapDefinition;
            if (EverParseIsSuccess(positionAfterCreateMapBody0))
            {
                positionAfterMapDefinition = positionAfterCreateMapBody0;
            }
            else
            {
                Err("_CREATE_MAP_BODY",
                    "MapDefinition",
                    EverParseErrorReasonOfResult(positionAfterCreateMapBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterMapDefinition = positionAfterCreateMapBody0;
            }
            if (EverParseIsError(positionAfterMapDefinition))
            {
                positionAfterCreateMapBody = positionAfterMapDefinition;
            }
            else
            {
                /* Validating field InnerMapHandle */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                                  (InputLength - positionAfterMapDefinition);
                uint64_t positionAfterCreateMapBody0;
                if (!hasEnoughBytes0)
                {
                    positionAfterCreateMapBody0 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterMapDefinition);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterMapDefinition +
                        (uint64_t)(uint32_t)(uint8_t)8U;
                    uint64_t result = positionAfterMapDefinition;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterCreateMapBody;
                            if (hasBytes)
                            {
                                positionAfterCreateMapBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterCreateMapBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(positionAfterCreateMapBody))
                            {
                                res = positionAfterCreateMapBody;
                            }
                            else
                            {
                                Err("_CREATE_MAP_BODY",
                                    "InnerMapHandle.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterCreateMapBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterCreateMapBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterCreateMapBody0 = res;
                }
                uint64_t positionAfterInnerMapHandle;
                if (EverParseIsSuccess(positionAfterCreateMapBody0))
                {
                    positionAfterInnerMapHandle = positionAfterCreateMapBody0;
                }
                else
                {
                    Err("_CREATE_MAP_BODY",
                        "InnerMapHandle",
                        EverParseErrorReasonOfResult(
                            positionAfterCreateMapBody0),
                        Ctxt,
                        Input,
                        positionAfterMapDefinition);
                    positionAfterInnerMapHandle = positionAfterCreateMapBody0;
                }
                if (EverParseIsError(positionAfterInnerMapHandle))
                {
                    positionAfterCreateMapBody = positionAfterInnerMapHandle;
                }
                else
                {
                    /* Validating field Data */
                    BOOLEAN
                    hasEnoughBytes =
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)EBPFPROTOCOL____CREATE_MAP_DATA_OFFSET) <=
                        (InputLength - positionAfterInnerMapHandle);
                    uint64_t positionAfterCreateMapBody0;
                    if (!hasEnoughBytes)
                    {
                        positionAfterCreateMapBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterInnerMapHandle);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterInnerMapHandle +
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____CREATE_MAP_DATA_OFFSET);
                        uint64_t result = positionAfterInnerMapHandle;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterCreateMapBody;
                                if (hasBytes)
                                {
                                    positionAfterCreateMapBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterCreateMapBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterCreateMapBody))
                                {
                                    res = positionAfterCreateMapBody;
                                }
                                else
                                {
                                    Err("_CREATE_MAP_BODY",
                                        "Data.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterCreateMapBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res = positionAfterCreateMapBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterCreateMapBody0 = res;
                    }
                    if (EverParseIsSuccess(positionAfterCreateMapBody0))
                    {
                        positionAfterCreateMapBody =
                            positionAfterCreateMapBody0;
                    }
                    else
                    {
                        Err("_CREATE_MAP_BODY",
                            "Data",
                            EverParseErrorReasonOfResult(
                                positionAfterCreateMapBody0),
                            Ctxt,
                            Input,
                            positionAfterInnerMapHandle);
                        positionAfterCreateMapBody =
                            positionAfterCreateMapBody0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterCreateMapBody))
    {
        return positionAfterCreateMapBody;
    }
    Err("_CREATE_MAP_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterCreateMapBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterCreateMapBody;
}

static inline uint64_t
ValidateLoadCodeBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterLoadCodeBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterLoadCodeBody = positionAfternone;
    }
    else
    {
        BOOLEAN noneConstraintIsOk =
            MessageLength >= (uint16_t)EBPFPROTOCOL____LOAD_CODE_CODE_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterLoadCodeBody = positionAfternone1;
        }
        else
        {
            /* Validating field ProgramHandle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterLoadCodeBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterLoadCodeBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterLoadCodeBody;
                        if (hasBytes)
                        {
                            positionAfterLoadCodeBody = position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterLoadCodeBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterLoadCodeBody))
                        {
                            res = positionAfterLoadCodeBody;
                        }
                        else
                        {
                            Err("_LOAD_CODE_BODY",
                                "ProgramHandle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterLoadCodeBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterLoadCodeBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterLoadCodeBody0 = res;
            }
            uint64_t positionAfterProgramHandle;
            if (EverParseIsSuccess(positionAfterLoadCodeBody0))
            {
                positionAfterProgramHandle = positionAfterLoadCodeBody0;
            }
            else
            {
                Err("_LOAD_CODE_BODY",
                    "ProgramHandle",
                    EverParseErrorReasonOfResult(positionAfterLoadCodeBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterProgramHandle = positionAfterLoadCodeBody0;
            }
            if (EverParseIsError(positionAfterProgramHandle))
            {
                positionAfterLoadCodeBody = positionAfterProgramHandle;
            }
            else
            {
                /* Checking that we have enough space for a UINT32, i.e., 4
                 * bytes */
                BOOLEAN hasBytes0 =
                    (uint64_t)4U <= (InputLength - positionAfterProgramHandle);
                uint64_t positionAfternone2;
                if (hasBytes0)
                {
                    positionAfternone2 =
                        positionAfterProgramHandle + (uint64_t)4U;
                }
                else
                {
                    positionAfternone2 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterProgramHandle);
                }
                uint64_t positionAfterLoadCodeBody0;
                if (EverParseIsError(positionAfternone2))
                {
                    positionAfterLoadCodeBody0 = positionAfternone2;
                }
                else
                {
                    uint32_t none1 =
                        Load32Le(Input + (uint32_t)positionAfterProgramHandle);
                    BOOLEAN noneConstraintIsOk1 =
                        none1 <= (uint32_t)EBPFPROTOCOL____EBPF_CODE_TYPE_MAX;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                        noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3))
                    {
                        positionAfterLoadCodeBody0 = positionAfternone3;
                    }
                    else
                    {
                        /* Validating field Code */
                        BOOLEAN
                        hasEnoughBytes =
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____LOAD_CODE_CODE_OFFSET) <=
                            (InputLength - positionAfternone3);
                        uint64_t positionAfterLoadCodeBody;
                        if (!hasEnoughBytes)
                        {
                            positionAfterLoadCodeBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfternone3);
                        }
                        else
                        {
                            uint8_t *truncatedInput = Input;
                            uint64_t truncatedInputLength =
                                positionAfternone3 +
                                (uint64_t)(uint32_t)(
                                    MessageLength -
                                    (uint16_t)
                                        EBPFPROTOCOL____LOAD_CODE_CODE_OFFSET);
                            uint64_t result = positionAfternone3;
                            while (TRUE)
                            {
                                uint64_t position = *&result;
                                BOOLEAN ite;
                                if (!((uint64_t)1U <=
                                      (truncatedInputLength - position)))
                                {
                                    ite = TRUE;
                                }
                                else
                                {
                                    /* Checking that we have enough space for a
                                     * UINT8, i.e., 1 byte */
                                    BOOLEAN hasBytes =
                                        (uint64_t)1U <=
                                        (truncatedInputLength - position);
                                    uint64_t positionAfterLoadCodeBody;
                                    if (hasBytes)
                                    {
                                        positionAfterLoadCodeBody =
                                            position + (uint64_t)1U;
                                    }
                                    else
                                    {
                                        positionAfterLoadCodeBody =
                                            EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                position);
                                    }
                                    uint64_t res;
                                    if (EverParseIsSuccess(
                                            positionAfterLoadCodeBody))
                                    {
                                        res = positionAfterLoadCodeBody;
                                    }
                                    else
                                    {
                                        Err("_LOAD_CODE_BODY",
                                            "Code.element",
                                            EverParseErrorReasonOfResult(
                                                positionAfterLoadCodeBody),
                                            Ctxt,
                                            truncatedInput,
                                            position);
                                        res = positionAfterLoadCodeBody;
                                    }
                                    uint64_t result1 = res;
                                    result = result1;
                                    ite = EverParseIsError(result1);
                                }
                                if (ite)
                                {
                                    break;
                                }
                            }
                            uint64_t res = result;
                            positionAfterLoadCodeBody = res;
                        }
                        if (EverParseIsSuccess(positionAfterLoadCodeBody))
                        {
                            positionAfterLoadCodeBody0 =
                                positionAfterLoadCodeBody;
                        }
                        else
                        {
                            Err("_LOAD_CODE_BODY",
                                "Code",
                                EverParseErrorReasonOfResult(
                                    positionAfterLoadCodeBody),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            positionAfterLoadCodeBody0 =
                                positionAfterLoadCodeBody;
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterLoadCodeBody0))
                {
                    positionAfterLoadCodeBody = positionAfterLoadCodeBody0;
                }
                else
                {
                    Err("_LOAD_CODE_BODY",
                        "none",
                        EverParseErrorReasonOfResult(
                            positionAfterLoadCodeBody0),
                        Ctxt,
                        Input,
                        positionAfterProgramHandle);
                    positionAfterLoadCodeBody = positionAfterLoadCodeBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterLoadCodeBody))
    {
        return positionAfterLoadCodeBody;
    }
    Err("_LOAD_CODE_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterLoadCodeBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterLoadCodeBody;
}

static inline uint64_t
ValidateMapFindElementBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapFindElementBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapFindElementBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >= (uint16_t)EBPFPROTOCOL____FIND_ELEMENT_KEY_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapFindElementBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapFindElementBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapFindElementBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapFindElementBody;
                        if (hasBytes)
                        {
                            positionAfterMapFindElementBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapFindElementBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterMapFindElementBody))
                        {
                            res = positionAfterMapFindElementBody;
                        }
                        else
                        {
                            Err("_MAP_FIND_ELEMENT_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapFindElementBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapFindElementBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapFindElementBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterMapFindElementBody0))
            {
                positionAfterHandle = positionAfterMapFindElementBody0;
            }
            else
            {
                Err("_MAP_FIND_ELEMENT_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapFindElementBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterMapFindElementBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterMapFindElementBody = positionAfterHandle;
            }
            else
            {
                /* Validating field FindAndDelete */
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes0 =
                    (uint64_t)1U <= (InputLength - positionAfterHandle);
                uint64_t positionAfterMapFindElementBody0;
                if (hasBytes0)
                {
                    positionAfterMapFindElementBody0 =
                        positionAfterHandle + (uint64_t)1U;
                }
                else
                {
                    positionAfterMapFindElementBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterHandle);
                }
                uint64_t res0;
                if (EverParseIsSuccess(positionAfterMapFindElementBody0))
                {
                    res0 = positionAfterMapFindElementBody0;
                }
                else
                {
                    Err("_MAP_FIND_ELEMENT_BODY",
                        "FindAndDelete",
                        EverParseErrorReasonOfResult(
                            positionAfterMapFindElementBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    res0 = positionAfterMapFindElementBody0;
                }
                uint64_t positionAfterFindAndDelete = res0;
                if (EverParseIsError(positionAfterFindAndDelete))
                {
                    positionAfterMapFindElementBody =
                        positionAfterFindAndDelete;
                }
                else
                {
                    /* Validating field Key */
                    BOOLEAN
                    hasEnoughBytes =
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____FIND_ELEMENT_KEY_OFFSET) <=
                        (InputLength - positionAfterFindAndDelete);
                    uint64_t positionAfterMapFindElementBody0;
                    if (!hasEnoughBytes)
                    {
                        positionAfterMapFindElementBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterFindAndDelete);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterFindAndDelete +
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____FIND_ELEMENT_KEY_OFFSET);
                        uint64_t result = positionAfterFindAndDelete;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterMapFindElementBody;
                                if (hasBytes)
                                {
                                    positionAfterMapFindElementBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterMapFindElementBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterMapFindElementBody))
                                {
                                    res = positionAfterMapFindElementBody;
                                }
                                else
                                {
                                    Err("_MAP_FIND_ELEMENT_BODY",
                                        "Key.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterMapFindElementBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res = positionAfterMapFindElementBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterMapFindElementBody0 = res;
                    }
                    if (EverParseIsSuccess(positionAfterMapFindElementBody0))
                    {
                        positionAfterMapFindElementBody =
                            positionAfterMapFindElementBody0;
                    }
                    else
                    {
                        Err("_MAP_FIND_ELEMENT_BODY",
                            "Key",
                            EverParseErrorReasonOfResult(
                                positionAfterMapFindElementBody0),
                            Ctxt,
                            Input,
                            positionAfterFindAndDelete);
                        positionAfterMapFindElementBody =
                            positionAfterMapFindElementBody0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapFindElementBody))
    {
        return positionAfterMapFindElementBody;
    }
    Err("_MAP_FIND_ELEMENT_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapFindElementBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapFindElementBody;
}

static inline uint64_t
ValidateMapUpdateBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapUpdateBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapUpdateBody = positionAfternone;
    }
    else
    {
        BOOLEAN noneConstraintIsOk =
            MessageLength >= (uint16_t)EBPFPROTOCOL____MAP_UPDATE_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapUpdateBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapUpdateBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapUpdateBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapUpdateBody;
                        if (hasBytes)
                        {
                            positionAfterMapUpdateBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapUpdateBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterMapUpdateBody))
                        {
                            res = positionAfterMapUpdateBody;
                        }
                        else
                        {
                            Err("_MAP_UPDATE_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapUpdateBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapUpdateBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapUpdateBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterMapUpdateBody0))
            {
                positionAfterHandle = positionAfterMapUpdateBody0;
            }
            else
            {
                Err("_MAP_UPDATE_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(positionAfterMapUpdateBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterMapUpdateBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterMapUpdateBody = positionAfterHandle;
            }
            else
            {
                /* Checking that we have enough space for a UINT32, i.e., 4
                 * bytes */
                BOOLEAN hasBytes0 =
                    (uint64_t)4U <= (InputLength - positionAfterHandle);
                uint64_t positionAfternone2;
                if (hasBytes0)
                {
                    positionAfternone2 = positionAfterHandle + (uint64_t)4U;
                }
                else
                {
                    positionAfternone2 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterHandle);
                }
                uint64_t positionAfterMapUpdateBody0;
                if (EverParseIsError(positionAfternone2))
                {
                    positionAfterMapUpdateBody0 = positionAfternone2;
                }
                else
                {
                    uint32_t none1 =
                        Load32Le(Input + (uint32_t)positionAfterHandle);
                    BOOLEAN noneConstraintIsOk1 =
                        none1 <= (uint32_t)EBPFPROTOCOL____EBPF_MAP_OPTION_MAX;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                        noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3))
                    {
                        positionAfterMapUpdateBody0 = positionAfternone3;
                    }
                    else
                    {
                        /* Validating field Data */
                        BOOLEAN
                        hasEnoughBytes =
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____MAP_UPDATE_DATA_OFFSET) <=
                            (InputLength - positionAfternone3);
                        uint64_t positionAfterMapUpdateBody;
                        if (!hasEnoughBytes)
                        {
                            positionAfterMapUpdateBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfternone3);
                        }
                        else
                        {
                            uint8_t *truncatedInput = Input;
                            uint64_t truncatedInputLength =
                                positionAfternone3 +
                                (uint64_t)(uint32_t)(
                                    MessageLength -
                                    (uint16_t)
                                        EBPFPROTOCOL____MAP_UPDATE_DATA_OFFSET);
                            uint64_t result = positionAfternone3;
                            while (TRUE)
                            {
                                uint64_t position = *&result;
                                BOOLEAN ite;
                                if (!((uint64_t)1U <=
                                      (truncatedInputLength - position)))
                                {
                                    ite = TRUE;
                                }
                                else
                                {
                                    /* Checking that we have enough space for a
                                     * UINT8, i.e., 1 byte */
                                    BOOLEAN hasBytes =
                                        (uint64_t)1U <=
                                        (truncatedInputLength - position);
                                    uint64_t positionAfterMapUpdateBody;
                                    if (hasBytes)
                                    {
                                        positionAfterMapUpdateBody =
                                            position + (uint64_t)1U;
                                    }
                                    else
                                    {
                                        positionAfterMapUpdateBody =
                                            EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                position);
                                    }
                                    uint64_t res;
                                    if (EverParseIsSuccess(
                                            positionAfterMapUpdateBody))
                                    {
                                        res = positionAfterMapUpdateBody;
                                    }
                                    else
                                    {
                                        Err("_MAP_UPDATE_BODY",
                                            "Data.element",
                                            EverParseErrorReasonOfResult(
                                                positionAfterMapUpdateBody),
                                            Ctxt,
                                            truncatedInput,
                                            position);
                                        res = positionAfterMapUpdateBody;
                                    }
                                    uint64_t result1 = res;
                                    result = result1;
                                    ite = EverParseIsError(result1);
                                }
                                if (ite)
                                {
                                    break;
                                }
                            }
                            uint64_t res = result;
                            positionAfterMapUpdateBody = res;
                        }
                        if (EverParseIsSuccess(positionAfterMapUpdateBody))
                        {
                            positionAfterMapUpdateBody0 =
                                positionAfterMapUpdateBody;
                        }
                        else
                        {
                            Err("_MAP_UPDATE_BODY",
                                "Data",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapUpdateBody),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            positionAfterMapUpdateBody0 =
                                positionAfterMapUpdateBody;
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterMapUpdateBody0))
                {
                    positionAfterMapUpdateBody = positionAfterMapUpdateBody0;
                }
                else
                {
                    Err("_MAP_UPDATE_BODY",
                        "none",
                        EverParseErrorReasonOfResult(
                            positionAfterMapUpdateBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    positionAfterMapUpdateBody = positionAfterMapUpdateBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapUpdateBody))
    {
        return positionAfterMapUpdateBody;
    }
    Err("_MAP_UPDATE_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapUpdateBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapUpdateBody;
}

static inline uint64_t
ValidateMapUpdateWithHandleBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapUpdateWithHandleBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapUpdateWithHandleBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____MAP_UPDATE_WITH_HANDLE_KEY_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapUpdateWithHandleBody = positionAfternone1;
        }
        else
        {
            /* Validating field MapHandle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapUpdateWithHandleBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapUpdateWithHandleBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapUpdateWithHandleBody;
                        if (hasBytes)
                        {
                            positionAfterMapUpdateWithHandleBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapUpdateWithHandleBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(
                                positionAfterMapUpdateWithHandleBody))
                        {
                            res = positionAfterMapUpdateWithHandleBody;
                        }
                        else
                        {
                            Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                                "MapHandle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapUpdateWithHandleBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapUpdateWithHandleBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapUpdateWithHandleBody0 = res;
            }
            uint64_t positionAfterMapHandle;
            if (EverParseIsSuccess(positionAfterMapUpdateWithHandleBody0))
            {
                positionAfterMapHandle = positionAfterMapUpdateWithHandleBody0;
            }
            else
            {
                Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                    "MapHandle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapUpdateWithHandleBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterMapHandle = positionAfterMapUpdateWithHandleBody0;
            }
            if (EverParseIsError(positionAfterMapHandle))
            {
                positionAfterMapUpdateWithHandleBody = positionAfterMapHandle;
            }
            else
            {
                /* Validating field ValueHandle */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                                  (InputLength - positionAfterMapHandle);
                uint64_t positionAfterMapUpdateWithHandleBody0;
                if (!hasEnoughBytes0)
                {
                    positionAfterMapUpdateWithHandleBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterMapHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterMapHandle +
                        (uint64_t)(uint32_t)(uint8_t)8U;
                    uint64_t result = positionAfterMapHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMapUpdateWithHandleBody;
                            if (hasBytes)
                            {
                                positionAfterMapUpdateWithHandleBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMapUpdateWithHandleBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterMapUpdateWithHandleBody))
                            {
                                res = positionAfterMapUpdateWithHandleBody;
                            }
                            else
                            {
                                Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                                    "ValueHandle.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMapUpdateWithHandleBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterMapUpdateWithHandleBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterMapUpdateWithHandleBody0 = res;
                }
                uint64_t positionAfterValueHandle;
                if (EverParseIsSuccess(positionAfterMapUpdateWithHandleBody0))
                {
                    positionAfterValueHandle =
                        positionAfterMapUpdateWithHandleBody0;
                }
                else
                {
                    Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                        "ValueHandle",
                        EverParseErrorReasonOfResult(
                            positionAfterMapUpdateWithHandleBody0),
                        Ctxt,
                        Input,
                        positionAfterMapHandle);
                    positionAfterValueHandle =
                        positionAfterMapUpdateWithHandleBody0;
                }
                if (EverParseIsError(positionAfterValueHandle))
                {
                    positionAfterMapUpdateWithHandleBody =
                        positionAfterValueHandle;
                }
                else
                {
                    /* Checking that we have enough space for a UINT32, i.e., 4
                     * bytes */
                    BOOLEAN hasBytes0 =
                        (uint64_t)4U <=
                        (InputLength - positionAfterValueHandle);
                    uint64_t positionAfternone2;
                    if (hasBytes0)
                    {
                        positionAfternone2 =
                            positionAfterValueHandle + (uint64_t)4U;
                    }
                    else
                    {
                        positionAfternone2 = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterValueHandle);
                    }
                    uint64_t positionAfterMapUpdateWithHandleBody0;
                    if (EverParseIsError(positionAfternone2))
                    {
                        positionAfterMapUpdateWithHandleBody0 =
                            positionAfternone2;
                    }
                    else
                    {
                        uint32_t none1 = Load32Le(
                            Input + (uint32_t)positionAfterValueHandle);
                        BOOLEAN noneConstraintIsOk1 =
                            none1 <=
                            (uint32_t)EBPFPROTOCOL____EBPF_MAP_OPTION_MAX;
                        uint64_t positionAfternone3 =
                            EverParseCheckConstraintOk(
                                noneConstraintIsOk1, positionAfternone2);
                        if (EverParseIsError(positionAfternone3))
                        {
                            positionAfterMapUpdateWithHandleBody0 =
                                positionAfternone3;
                        }
                        else
                        {
                            /* Validating field Key */
                            BOOLEAN
                            hasEnoughBytes =
                                (uint64_t)(uint32_t)(
                                    MessageLength -
                                    (uint16_t)
                                        EBPFPROTOCOL____MAP_UPDATE_WITH_HANDLE_KEY_OFFSET) <=
                                (InputLength - positionAfternone3);
                            uint64_t positionAfterMapUpdateWithHandleBody;
                            if (!hasEnoughBytes)
                            {
                                positionAfterMapUpdateWithHandleBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfternone3);
                            }
                            else
                            {
                                uint8_t *truncatedInput = Input;
                                uint64_t truncatedInputLength =
                                    positionAfternone3 +
                                    (uint64_t)(uint32_t)(
                                        MessageLength -
                                        (uint16_t)
                                            EBPFPROTOCOL____MAP_UPDATE_WITH_HANDLE_KEY_OFFSET);
                                uint64_t result = positionAfternone3;
                                while (TRUE)
                                {
                                    uint64_t position = *&result;
                                    BOOLEAN ite;
                                    if (!((uint64_t)1U <=
                                          (truncatedInputLength - position)))
                                    {
                                        ite = TRUE;
                                    }
                                    else
                                    {
                                        /* Checking that we have enough space
                                         * for a UINT8, i.e., 1 byte */
                                        BOOLEAN hasBytes =
                                            (uint64_t)1U <=
                                            (truncatedInputLength - position);
                                        uint64_t
                                            positionAfterMapUpdateWithHandleBody;
                                        if (hasBytes)
                                        {
                                            positionAfterMapUpdateWithHandleBody =
                                                position + (uint64_t)1U;
                                        }
                                        else
                                        {
                                            positionAfterMapUpdateWithHandleBody =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    position);
                                        }
                                        uint64_t res;
                                        if (EverParseIsSuccess(
                                                positionAfterMapUpdateWithHandleBody))
                                        {
                                            res =
                                                positionAfterMapUpdateWithHandleBody;
                                        }
                                        else
                                        {
                                            Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                                                "Key.element",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterMapUpdateWithHandleBody),
                                                Ctxt,
                                                truncatedInput,
                                                position);
                                            res =
                                                positionAfterMapUpdateWithHandleBody;
                                        }
                                        uint64_t result1 = res;
                                        result = result1;
                                        ite = EverParseIsError(result1);
                                    }
                                    if (ite)
                                    {
                                        break;
                                    }
                                }
                                uint64_t res = result;
                                positionAfterMapUpdateWithHandleBody = res;
                            }
                            if (EverParseIsSuccess(
                                    positionAfterMapUpdateWithHandleBody))
                            {
                                positionAfterMapUpdateWithHandleBody0 =
                                    positionAfterMapUpdateWithHandleBody;
                            }
                            else
                            {
                                Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                                    "Key",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMapUpdateWithHandleBody),
                                    Ctxt,
                                    Input,
                                    positionAfternone3);
                                positionAfterMapUpdateWithHandleBody0 =
                                    positionAfterMapUpdateWithHandleBody;
                            }
                        }
                    }
                    if (EverParseIsSuccess(
                            positionAfterMapUpdateWithHandleBody0))
                    {
                        positionAfterMapUpdateWithHandleBody =
                            positionAfterMapUpdateWithHandleBody0;
                    }
                    else
                    {
                        Err("_MAP_UPDATE_WITH_HANDLE_BODY",
                            "none",
                            EverParseErrorReasonOfResult(
                                positionAfterMapUpdateWithHandleBody0),
                            Ctxt,
                            Input,
                            positionAfterValueHandle);
                        positionAfterMapUpdateWithHandleBody =
                            positionAfterMapUpdateWithHandleBody0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapUpdateWithHandleBody))
    {
        return positionAfterMapUpdateWithHandleBody;
    }
    Err("_MAP_UPDATE_WITH_HANDLE_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapUpdateWithHandleBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapUpdateWithHandleBody;
}

static inline uint64_t
ValidateMapDeleteElementBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapDeleteElementBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapDeleteElementBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____DELETE_ELEMENT_KEY_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapDeleteElementBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapDeleteElementBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapDeleteElementBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapDeleteElementBody;
                        if (hasBytes)
                        {
                            positionAfterMapDeleteElementBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapDeleteElementBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(
                                positionAfterMapDeleteElementBody))
                        {
                            res = positionAfterMapDeleteElementBody;
                        }
                        else
                        {
                            Err("_MAP_DELETE_ELEMENT_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapDeleteElementBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapDeleteElementBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapDeleteElementBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterMapDeleteElementBody0))
            {
                positionAfterHandle = positionAfterMapDeleteElementBody0;
            }
            else
            {
                Err("_MAP_DELETE_ELEMENT_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapDeleteElementBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterMapDeleteElementBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterMapDeleteElementBody = positionAfterHandle;
            }
            else
            {
                /* Validating field Key */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)(uint32_t)(
                        MessageLength -
                        (uint16_t)EBPFPROTOCOL____DELETE_ELEMENT_KEY_OFFSET) <=
                    (InputLength - positionAfterHandle);
                uint64_t positionAfterMapDeleteElementBody0;
                if (!hasEnoughBytes)
                {
                    positionAfterMapDeleteElementBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterHandle +
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____DELETE_ELEMENT_KEY_OFFSET);
                    uint64_t result = positionAfterHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMapDeleteElementBody;
                            if (hasBytes)
                            {
                                positionAfterMapDeleteElementBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMapDeleteElementBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterMapDeleteElementBody))
                            {
                                res = positionAfterMapDeleteElementBody;
                            }
                            else
                            {
                                Err("_MAP_DELETE_ELEMENT_BODY",
                                    "Key.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMapDeleteElementBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterMapDeleteElementBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterMapDeleteElementBody0 = res;
                }
                if (EverParseIsSuccess(positionAfterMapDeleteElementBody0))
                {
                    positionAfterMapDeleteElementBody =
                        positionAfterMapDeleteElementBody0;
                }
                else
                {
                    Err("_MAP_DELETE_ELEMENT_BODY",
                        "Key",
                        EverParseErrorReasonOfResult(
                            positionAfterMapDeleteElementBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    positionAfterMapDeleteElementBody =
                        positionAfterMapDeleteElementBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapDeleteElementBody))
    {
        return positionAfterMapDeleteElementBody;
    }
    Err("_MAP_DELETE_ELEMENT_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapDeleteElementBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapDeleteElementBody;
}

static inline uint64_t
ValidateMapGetNextKeyBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapGetNextKeyBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapGetNextKeyBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____GET_NEXT_KEY_PREVIOUS_KEY_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapGetNextKeyBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapGetNextKeyBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapGetNextKeyBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapGetNextKeyBody;
                        if (hasBytes)
                        {
                            positionAfterMapGetNextKeyBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapGetNextKeyBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterMapGetNextKeyBody))
                        {
                            res = positionAfterMapGetNextKeyBody;
                        }
                        else
                        {
                            Err("_MAP_GET_NEXT_KEY_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapGetNextKeyBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapGetNextKeyBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapGetNextKeyBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterMapGetNextKeyBody0))
            {
                positionAfterHandle = positionAfterMapGetNextKeyBody0;
            }
            else
            {
                Err("_MAP_GET_NEXT_KEY_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapGetNextKeyBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterMapGetNextKeyBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterMapGetNextKeyBody = positionAfterHandle;
            }
            else
            {
                /* Validating field PreviousKey */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)(uint32_t)(
                        MessageLength -
                        (uint16_t)
                            EBPFPROTOCOL____GET_NEXT_KEY_PREVIOUS_KEY_OFFSET) <=
                    (InputLength - positionAfterHandle);
                uint64_t positionAfterMapGetNextKeyBody0;
                if (!hasEnoughBytes)
                {
                    positionAfterMapGetNextKeyBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterHandle +
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____GET_NEXT_KEY_PREVIOUS_KEY_OFFSET);
                    uint64_t result = positionAfterHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMapGetNextKeyBody;
                            if (hasBytes)
                            {
                                positionAfterMapGetNextKeyBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMapGetNextKeyBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterMapGetNextKeyBody))
                            {
                                res = positionAfterMapGetNextKeyBody;
                            }
                            else
                            {
                                Err("_MAP_GET_NEXT_KEY_BODY",
                                    "PreviousKey.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMapGetNextKeyBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterMapGetNextKeyBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterMapGetNextKeyBody0 = res;
                }
                if (EverParseIsSuccess(positionAfterMapGetNextKeyBody0))
                {
                    positionAfterMapGetNextKeyBody =
                        positionAfterMapGetNextKeyBody0;
                }
                else
                {
                    Err("_MAP_GET_NEXT_KEY_BODY",
                        "PreviousKey",
                        EverParseErrorReasonOfResult(
                            positionAfterMapGetNextKeyBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    positionAfterMapGetNextKeyBody =
                        positionAfterMapGetNextKeyBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapGetNextKeyBody))
    {
        return positionAfterMapGetNextKeyBody;
    }
    Err("_MAP_GET_NEXT_KEY_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapGetNextKeyBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapGetNextKeyBody;
}

static inline uint64_t
ValidateUpdatePinningBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterUpdatePinningBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterUpdatePinningBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____UPDATE_PINNING_PATH_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterUpdatePinningBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterUpdatePinningBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterUpdatePinningBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterUpdatePinningBody;
                        if (hasBytes)
                        {
                            positionAfterUpdatePinningBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterUpdatePinningBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterUpdatePinningBody))
                        {
                            res = positionAfterUpdatePinningBody;
                        }
                        else
                        {
                            Err("_UPDATE_PINNING_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterUpdatePinningBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterUpdatePinningBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterUpdatePinningBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterUpdatePinningBody0))
            {
                positionAfterHandle = positionAfterUpdatePinningBody0;
            }
            else
            {
                Err("_UPDATE_PINNING_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(
                        positionAfterUpdatePinningBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterUpdatePinningBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterUpdatePinningBody = positionAfterHandle;
            }
            else
            {
                /* Validating field Path */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)(uint32_t)(
                        MessageLength -
                        (uint16_t)EBPFPROTOCOL____UPDATE_PINNING_PATH_OFFSET) <=
                    (InputLength - positionAfterHandle);
                uint64_t positionAfterUpdatePinningBody0;
                if (!hasEnoughBytes)
                {
                    positionAfterUpdatePinningBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterHandle +
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____UPDATE_PINNING_PATH_OFFSET);
                    uint64_t result = positionAfterHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterUpdatePinningBody;
                            if (hasBytes)
                            {
                                positionAfterUpdatePinningBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterUpdatePinningBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterUpdatePinningBody))
                            {
                                res = positionAfterUpdatePinningBody;
                            }
                            else
                            {
                                Err("_UPDATE_PINNING_BODY",
                                    "Path.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterUpdatePinningBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterUpdatePinningBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterUpdatePinningBody0 = res;
                }
                if (EverParseIsSuccess(positionAfterUpdatePinningBody0))
                {
                    positionAfterUpdatePinningBody =
                        positionAfterUpdatePinningBody0;
                }
                else
                {
                    Err("_UPDATE_PINNING_BODY",
                        "Path",
                        EverParseErrorReasonOfResult(
                            positionAfterUpdatePinningBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    positionAfterUpdatePinningBody =
                        positionAfterUpdatePinningBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterUpdatePinningBody))
    {
        return positionAfterUpdatePinningBody;
    }
    Err("_UPDATE_PINNING_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterUpdatePinningBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterUpdatePinningBody;
}

static inline uint64_t
ValidateGetPinnedObjectBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterGetPinnedObjectBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterGetPinnedObjectBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____GET_PINNED_OBJECT_PATH_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterGetPinnedObjectBody = positionAfternone1;
        }
        else
        {
            /* Validating field Path */
            BOOLEAN
            hasEnoughBytes =
                (uint64_t)(uint32_t)(
                    MessageLength -
                    (uint16_t)EBPFPROTOCOL____GET_PINNED_OBJECT_PATH_OFFSET) <=
                (InputLength - positionAfternone1);
            uint64_t positionAfterGetPinnedObjectBody0;
            if (!hasEnoughBytes)
            {
                positionAfterGetPinnedObjectBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 +
                    (uint64_t)(uint32_t)(
                        MessageLength -
                        (uint16_t)
                            EBPFPROTOCOL____GET_PINNED_OBJECT_PATH_OFFSET);
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterGetPinnedObjectBody;
                        if (hasBytes)
                        {
                            positionAfterGetPinnedObjectBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterGetPinnedObjectBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(
                                positionAfterGetPinnedObjectBody))
                        {
                            res = positionAfterGetPinnedObjectBody;
                        }
                        else
                        {
                            Err("_GET_PINNED_OBJECT_BODY",
                                "Path.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterGetPinnedObjectBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterGetPinnedObjectBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterGetPinnedObjectBody0 = res;
            }
            if (EverParseIsSuccess(positionAfterGetPinnedObjectBody0))
            {
                positionAfterGetPinnedObjectBody =
                    positionAfterGetPinnedObjectBody0;
            }
            else
            {
                Err("_GET_PINNED_OBJECT_BODY",
                    "Path",
                    EverParseErrorReasonOfResult(
                        positionAfterGetPinnedObjectBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterGetPinnedObjectBody =
                    positionAfterGetPinnedObjectBody0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterGetPinnedObjectBody))
    {
        return positionAfterGetPinnedObjectBody;
    }
    Err("_GET_PINNED_OBJECT_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterGetPinnedObjectBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterGetPinnedObjectBody;
}

static inline uint64_t
ValidateLinkProgramBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterLinkProgramBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterLinkProgramBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >= (uint16_t)EBPFPROTOCOL____LINK_PROGRAM_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterLinkProgramBody = positionAfternone1;
        }
        else
        {
            /* Validating field ProgramHandle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterLinkProgramBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterLinkProgramBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterLinkProgramBody;
                        if (hasBytes)
                        {
                            positionAfterLinkProgramBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterLinkProgramBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterLinkProgramBody))
                        {
                            res = positionAfterLinkProgramBody;
                        }
                        else
                        {
                            Err("_LINK_PROGRAM_BODY",
                                "ProgramHandle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterLinkProgramBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterLinkProgramBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterLinkProgramBody0 = res;
            }
            uint64_t positionAfterProgramHandle;
            if (EverParseIsSuccess(positionAfterLinkProgramBody0))
            {
                positionAfterProgramHandle = positionAfterLinkProgramBody0;
            }
            else
            {
                Err("_LINK_PROGRAM_BODY",
                    "ProgramHandle",
                    EverParseErrorReasonOfResult(positionAfterLinkProgramBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterProgramHandle = positionAfterLinkProgramBody0;
            }
            if (EverParseIsError(positionAfterProgramHandle))
            {
                positionAfterLinkProgramBody = positionAfterProgramHandle;
            }
            else
            {
                /* Validating field AttachType */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)16U <=
                                  (InputLength - positionAfterProgramHandle);
                uint64_t positionAfterLinkProgramBody0;
                if (!hasEnoughBytes0)
                {
                    positionAfterLinkProgramBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterProgramHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterProgramHandle +
                        (uint64_t)(uint32_t)(uint8_t)16U;
                    uint64_t result = positionAfterProgramHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterLinkProgramBody;
                            if (hasBytes)
                            {
                                positionAfterLinkProgramBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterLinkProgramBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterLinkProgramBody))
                            {
                                res = positionAfterLinkProgramBody;
                            }
                            else
                            {
                                Err("_LINK_PROGRAM_BODY",
                                    "AttachType.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterLinkProgramBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterLinkProgramBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterLinkProgramBody0 = res;
                }
                uint64_t positionAfterAttachType;
                if (EverParseIsSuccess(positionAfterLinkProgramBody0))
                {
                    positionAfterAttachType = positionAfterLinkProgramBody0;
                }
                else
                {
                    Err("_LINK_PROGRAM_BODY",
                        "AttachType",
                        EverParseErrorReasonOfResult(
                            positionAfterLinkProgramBody0),
                        Ctxt,
                        Input,
                        positionAfterProgramHandle);
                    positionAfterAttachType = positionAfterLinkProgramBody0;
                }
                if (EverParseIsError(positionAfterAttachType))
                {
                    positionAfterLinkProgramBody = positionAfterAttachType;
                }
                else
                {
                    /* Validating field Data */
                    BOOLEAN
                    hasEnoughBytes =
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____LINK_PROGRAM_DATA_OFFSET) <=
                        (InputLength - positionAfterAttachType);
                    uint64_t positionAfterLinkProgramBody0;
                    if (!hasEnoughBytes)
                    {
                        positionAfterLinkProgramBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterAttachType);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterAttachType +
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____LINK_PROGRAM_DATA_OFFSET);
                        uint64_t result = positionAfterAttachType;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterLinkProgramBody;
                                if (hasBytes)
                                {
                                    positionAfterLinkProgramBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterLinkProgramBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterLinkProgramBody))
                                {
                                    res = positionAfterLinkProgramBody;
                                }
                                else
                                {
                                    Err("_LINK_PROGRAM_BODY",
                                        "Data.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterLinkProgramBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res = positionAfterLinkProgramBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterLinkProgramBody0 = res;
                    }
                    if (EverParseIsSuccess(positionAfterLinkProgramBody0))
                    {
                        positionAfterLinkProgramBody =
                            positionAfterLinkProgramBody0;
                    }
                    else
                    {
                        Err("_LINK_PROGRAM_BODY",
                            "Data",
                            EverParseErrorReasonOfResult(
                                positionAfterLinkProgramBody0),
                            Ctxt,
                            Input,
                            positionAfterAttachType);
                        positionAfterLinkProgramBody =
                            positionAfterLinkProgramBody0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterLinkProgramBody))
    {
        return positionAfterLinkProgramBody;
    }
    Err("_LINK_PROGRAM_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterLinkProgramBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterLinkProgramBody;
}

static inline uint64_t
ValidateUnlinkProgramBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterUnlinkProgramBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterUnlinkProgramBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____UNLINK_PROGRAM_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterUnlinkProgramBody = positionAfternone1;
        }
        else
        {
            /* Validating field LinkHandle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterUnlinkProgramBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterUnlinkProgramBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterUnlinkProgramBody;
                        if (hasBytes)
                        {
                            positionAfterUnlinkProgramBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterUnlinkProgramBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterUnlinkProgramBody))
                        {
                            res = positionAfterUnlinkProgramBody;
                        }
                        else
                        {
                            Err("_UNLINK_PROGRAM_BODY",
                                "LinkHandle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterUnlinkProgramBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterUnlinkProgramBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterUnlinkProgramBody0 = res;
            }
            uint64_t positionAfterLinkHandle;
            if (EverParseIsSuccess(positionAfterUnlinkProgramBody0))
            {
                positionAfterLinkHandle = positionAfterUnlinkProgramBody0;
            }
            else
            {
                Err("_UNLINK_PROGRAM_BODY",
                    "LinkHandle",
                    EverParseErrorReasonOfResult(
                        positionAfterUnlinkProgramBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterLinkHandle = positionAfterUnlinkProgramBody0;
            }
            if (EverParseIsError(positionAfterLinkHandle))
            {
                positionAfterUnlinkProgramBody = positionAfterLinkHandle;
            }
            else
            {
                /* Validating field ProgramHandle */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                                  (InputLength - positionAfterLinkHandle);
                uint64_t positionAfterUnlinkProgramBody0;
                if (!hasEnoughBytes0)
                {
                    positionAfterUnlinkProgramBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterLinkHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterLinkHandle +
                        (uint64_t)(uint32_t)(uint8_t)8U;
                    uint64_t result = positionAfterLinkHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterUnlinkProgramBody;
                            if (hasBytes)
                            {
                                positionAfterUnlinkProgramBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterUnlinkProgramBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterUnlinkProgramBody))
                            {
                                res = positionAfterUnlinkProgramBody;
                            }
                            else
                            {
                                Err("_UNLINK_PROGRAM_BODY",
                                    "ProgramHandle.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterUnlinkProgramBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterUnlinkProgramBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterUnlinkProgramBody0 = res;
                }
                uint64_t positionAfterProgramHandle;
                if (EverParseIsSuccess(positionAfterUnlinkProgramBody0))
                {
                    positionAfterProgramHandle =
                        positionAfterUnlinkProgramBody0;
                }
                else
                {
                    Err("_UNLINK_PROGRAM_BODY",
                        "ProgramHandle",
                        EverParseErrorReasonOfResult(
                            positionAfterUnlinkProgramBody0),
                        Ctxt,
                        Input,
                        positionAfterLinkHandle);
                    positionAfterProgramHandle =
                        positionAfterUnlinkProgramBody0;
                }
                if (EverParseIsError(positionAfterProgramHandle))
                {
                    positionAfterUnlinkProgramBody = positionAfterProgramHandle;
                }
                else
                {
                    /* Validating field AttachType */
                    BOOLEAN
                    hasEnoughBytes0 =
                        (uint64_t)(uint32_t)(uint8_t)16U <=
                        (InputLength - positionAfterProgramHandle);
                    uint64_t positionAfterUnlinkProgramBody0;
                    if (!hasEnoughBytes0)
                    {
                        positionAfterUnlinkProgramBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterProgramHandle);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterProgramHandle +
                            (uint64_t)(uint32_t)(uint8_t)16U;
                        uint64_t result = positionAfterProgramHandle;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterUnlinkProgramBody;
                                if (hasBytes)
                                {
                                    positionAfterUnlinkProgramBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterUnlinkProgramBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterUnlinkProgramBody))
                                {
                                    res = positionAfterUnlinkProgramBody;
                                }
                                else
                                {
                                    Err("_UNLINK_PROGRAM_BODY",
                                        "AttachType.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterUnlinkProgramBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res = positionAfterUnlinkProgramBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterUnlinkProgramBody0 = res;
                    }
                    uint64_t positionAfterAttachType;
                    if (EverParseIsSuccess(positionAfterUnlinkProgramBody0))
                    {
                        positionAfterAttachType =
                            positionAfterUnlinkProgramBody0;
                    }
                    else
                    {
                        Err("_UNLINK_PROGRAM_BODY",
                            "AttachType",
                            EverParseErrorReasonOfResult(
                                positionAfterUnlinkProgramBody0),
                            Ctxt,
                            Input,
                            positionAfterProgramHandle);
                        positionAfterAttachType =
                            positionAfterUnlinkProgramBody0;
                    }
                    if (EverParseIsError(positionAfterAttachType))
                    {
                        positionAfterUnlinkProgramBody =
                            positionAfterAttachType;
                    }
                    else
                    {
                        /* Validating field AttachDataPresent */
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes0 =
                            (uint64_t)1U <=
                            (InputLength - positionAfterAttachType);
                        uint64_t positionAfterUnlinkProgramBody0;
                        if (hasBytes0)
                        {
                            positionAfterUnlinkProgramBody0 =
                                positionAfterAttachType + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterUnlinkProgramBody0 =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterAttachType);
                        }
                        uint64_t res0;
                        if (EverParseIsSuccess(positionAfterUnlinkProgramBody0))
                        {
                            res0 = positionAfterUnlinkProgramBody0;
                        }
                        else
                        {
                            Err("_UNLINK_PROGRAM_BODY",
                                "AttachDataPresent",
                                EverParseErrorReasonOfResult(
                                    positionAfterUnlinkProgramBody0),
                                Ctxt,
                                Input,
                                positionAfterAttachType);
                            res0 = positionAfterUnlinkProgramBody0;
                        }
                        uint64_t positionAfterAttachDataPresent = res0;
                        if (EverParseIsError(positionAfterAttachDataPresent))
                        {
                            positionAfterUnlinkProgramBody =
                                positionAfterAttachDataPresent;
                        }
                        else
                        {
                            /* Validating field Data */
                            BOOLEAN
                            hasEnoughBytes =
                                (uint64_t)(uint32_t)(
                                    MessageLength -
                                    (uint16_t)
                                        EBPFPROTOCOL____UNLINK_PROGRAM_DATA_OFFSET) <=
                                (InputLength - positionAfterAttachDataPresent);
                            uint64_t positionAfterUnlinkProgramBody0;
                            if (!hasEnoughBytes)
                            {
                                positionAfterUnlinkProgramBody0 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfterAttachDataPresent);
                            }
                            else
                            {
                                uint8_t *truncatedInput = Input;
                                uint64_t truncatedInputLength =
                                    positionAfterAttachDataPresent +
                                    (uint64_t)(uint32_t)(
                                        MessageLength -
                                        (uint16_t)
                                            EBPFPROTOCOL____UNLINK_PROGRAM_DATA_OFFSET);
                                uint64_t result =
                                    positionAfterAttachDataPresent;
                                while (TRUE)
                                {
                                    uint64_t position = *&result;
                                    BOOLEAN ite;
                                    if (!((uint64_t)1U <=
                                          (truncatedInputLength - position)))
                                    {
                                        ite = TRUE;
                                    }
                                    else
                                    {
                                        /* Checking that we have enough space
                                         * for a UINT8, i.e., 1 byte */
                                        BOOLEAN hasBytes =
                                            (uint64_t)1U <=
                                            (truncatedInputLength - position);
                                        uint64_t positionAfterUnlinkProgramBody;
                                        if (hasBytes)
                                        {
                                            positionAfterUnlinkProgramBody =
                                                position + (uint64_t)1U;
                                        }
                                        else
                                        {
                                            positionAfterUnlinkProgramBody =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    position);
                                        }
                                        uint64_t res;
                                        if (EverParseIsSuccess(
                                                positionAfterUnlinkProgramBody))
                                        {
                                            res =
                                                positionAfterUnlinkProgramBody;
                                        }
                                        else
                                        {
                                            Err("_UNLINK_PROGRAM_BODY",
                                                "Data.element",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterUnlinkProgramBody),
                                                Ctxt,
                                                truncatedInput,
                                                position);
                                            res =
                                                positionAfterUnlinkProgramBody;
                                        }
                                        uint64_t result1 = res;
                                        result = result1;
                                        ite = EverParseIsError(result1);
                                    }
                                    if (ite)
                                    {
                                        break;
                                    }
                                }
                                uint64_t res = result;
                                positionAfterUnlinkProgramBody0 = res;
                            }
                            if (EverParseIsSuccess(
                                    positionAfterUnlinkProgramBody0))
                            {
                                positionAfterUnlinkProgramBody =
                                    positionAfterUnlinkProgramBody0;
                            }
                            else
                            {
                                Err("_UNLINK_PROGRAM_BODY",
                                    "Data",
                                    EverParseErrorReasonOfResult(
                                        positionAfterUnlinkProgramBody0),
                                    Ctxt,
                                    Input,
                                    positionAfterAttachDataPresent);
                                positionAfterUnlinkProgramBody =
                                    positionAfterUnlinkProgramBody0;
                            }
                        }
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterUnlinkProgramBody))
    {
        return positionAfterUnlinkProgramBody;
    }
    Err("_UNLINK_PROGRAM_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterUnlinkProgramBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterUnlinkProgramBody;
}

static inline uint64_t
ValidateMapWriteDataBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapWriteDataBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapWriteDataBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____MAP_WRITE_DATA_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapWriteDataBody = positionAfternone1;
        }
        else
        {
            /* Validating field MapHandle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapWriteDataBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapWriteDataBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapWriteDataBody;
                        if (hasBytes)
                        {
                            positionAfterMapWriteDataBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapWriteDataBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterMapWriteDataBody))
                        {
                            res = positionAfterMapWriteDataBody;
                        }
                        else
                        {
                            Err("_MAP_WRITE_DATA_BODY",
                                "MapHandle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapWriteDataBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapWriteDataBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapWriteDataBody0 = res;
            }
            uint64_t positionAfterMapHandle;
            if (EverParseIsSuccess(positionAfterMapWriteDataBody0))
            {
                positionAfterMapHandle = positionAfterMapWriteDataBody0;
            }
            else
            {
                Err("_MAP_WRITE_DATA_BODY",
                    "MapHandle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapWriteDataBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterMapHandle = positionAfterMapWriteDataBody0;
            }
            if (EverParseIsError(positionAfterMapHandle))
            {
                positionAfterMapWriteDataBody = positionAfterMapHandle;
            }
            else
            {
                /* Validating field Flags */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                                  (InputLength - positionAfterMapHandle);
                uint64_t positionAfterMapWriteDataBody0;
                if (!hasEnoughBytes0)
                {
                    positionAfterMapWriteDataBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterMapHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterMapHandle +
                        (uint64_t)(uint32_t)(uint8_t)8U;
                    uint64_t result = positionAfterMapHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMapWriteDataBody;
                            if (hasBytes)
                            {
                                positionAfterMapWriteDataBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMapWriteDataBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterMapWriteDataBody))
                            {
                                res = positionAfterMapWriteDataBody;
                            }
                            else
                            {
                                Err("_MAP_WRITE_DATA_BODY",
                                    "Flags.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMapWriteDataBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterMapWriteDataBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterMapWriteDataBody0 = res;
                }
                uint64_t positionAfterFlags;
                if (EverParseIsSuccess(positionAfterMapWriteDataBody0))
                {
                    positionAfterFlags = positionAfterMapWriteDataBody0;
                }
                else
                {
                    Err("_MAP_WRITE_DATA_BODY",
                        "Flags",
                        EverParseErrorReasonOfResult(
                            positionAfterMapWriteDataBody0),
                        Ctxt,
                        Input,
                        positionAfterMapHandle);
                    positionAfterFlags = positionAfterMapWriteDataBody0;
                }
                if (EverParseIsError(positionAfterFlags))
                {
                    positionAfterMapWriteDataBody = positionAfterFlags;
                }
                else
                {
                    /* Validating field Data */
                    BOOLEAN
                    hasEnoughBytes =
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____MAP_WRITE_DATA_DATA_OFFSET) <=
                        (InputLength - positionAfterFlags);
                    uint64_t positionAfterMapWriteDataBody0;
                    if (!hasEnoughBytes)
                    {
                        positionAfterMapWriteDataBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterFlags);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterFlags +
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____MAP_WRITE_DATA_DATA_OFFSET);
                        uint64_t result = positionAfterFlags;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterMapWriteDataBody;
                                if (hasBytes)
                                {
                                    positionAfterMapWriteDataBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterMapWriteDataBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterMapWriteDataBody))
                                {
                                    res = positionAfterMapWriteDataBody;
                                }
                                else
                                {
                                    Err("_MAP_WRITE_DATA_BODY",
                                        "Data.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterMapWriteDataBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res = positionAfterMapWriteDataBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterMapWriteDataBody0 = res;
                    }
                    if (EverParseIsSuccess(positionAfterMapWriteDataBody0))
                    {
                        positionAfterMapWriteDataBody =
                            positionAfterMapWriteDataBody0;
                    }
                    else
                    {
                        Err("_MAP_WRITE_DATA_BODY",
                            "Data",
                            EverParseErrorReasonOfResult(
                                positionAfterMapWriteDataBody0),
                            Ctxt,
                            Input,
                            positionAfterFlags);
                        positionAfterMapWriteDataBody =
                            positionAfterMapWriteDataBody0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapWriteDataBody))
    {
        return positionAfterMapWriteDataBody;
    }
    Err("_MAP_WRITE_DATA_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapWriteDataBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapWriteDataBody;
}

static inline uint64_t
ValidateLoadNativeModuleBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterLoadNativeModuleBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterLoadNativeModuleBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____LOAD_NATIVE_MODULE_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterLoadNativeModuleBody = positionAfternone1;
        }
        else
        {
            /* Validating field ModuleId */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)16U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterLoadNativeModuleBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterLoadNativeModuleBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)16U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterLoadNativeModuleBody;
                        if (hasBytes)
                        {
                            positionAfterLoadNativeModuleBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterLoadNativeModuleBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(
                                positionAfterLoadNativeModuleBody))
                        {
                            res = positionAfterLoadNativeModuleBody;
                        }
                        else
                        {
                            Err("_LOAD_NATIVE_MODULE_BODY",
                                "ModuleId.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterLoadNativeModuleBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterLoadNativeModuleBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterLoadNativeModuleBody0 = res;
            }
            uint64_t positionAfterModuleId;
            if (EverParseIsSuccess(positionAfterLoadNativeModuleBody0))
            {
                positionAfterModuleId = positionAfterLoadNativeModuleBody0;
            }
            else
            {
                Err("_LOAD_NATIVE_MODULE_BODY",
                    "ModuleId",
                    EverParseErrorReasonOfResult(
                        positionAfterLoadNativeModuleBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterModuleId = positionAfterLoadNativeModuleBody0;
            }
            if (EverParseIsError(positionAfterModuleId))
            {
                positionAfterLoadNativeModuleBody = positionAfterModuleId;
            }
            else
            {
                /* Validating field Data */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)(uint32_t)(
                        MessageLength -
                        (uint16_t)
                            EBPFPROTOCOL____LOAD_NATIVE_MODULE_DATA_OFFSET) <=
                    (InputLength - positionAfterModuleId);
                uint64_t positionAfterLoadNativeModuleBody0;
                if (!hasEnoughBytes)
                {
                    positionAfterLoadNativeModuleBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterModuleId);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterModuleId +
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____LOAD_NATIVE_MODULE_DATA_OFFSET);
                    uint64_t result = positionAfterModuleId;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterLoadNativeModuleBody;
                            if (hasBytes)
                            {
                                positionAfterLoadNativeModuleBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterLoadNativeModuleBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterLoadNativeModuleBody))
                            {
                                res = positionAfterLoadNativeModuleBody;
                            }
                            else
                            {
                                Err("_LOAD_NATIVE_MODULE_BODY",
                                    "Data.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterLoadNativeModuleBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterLoadNativeModuleBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterLoadNativeModuleBody0 = res;
                }
                if (EverParseIsSuccess(positionAfterLoadNativeModuleBody0))
                {
                    positionAfterLoadNativeModuleBody =
                        positionAfterLoadNativeModuleBody0;
                }
                else
                {
                    Err("_LOAD_NATIVE_MODULE_BODY",
                        "Data",
                        EverParseErrorReasonOfResult(
                            positionAfterLoadNativeModuleBody0),
                        Ctxt,
                        Input,
                        positionAfterModuleId);
                    positionAfterLoadNativeModuleBody =
                        positionAfterLoadNativeModuleBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterLoadNativeModuleBody))
    {
        return positionAfterLoadNativeModuleBody;
    }
    Err("_LOAD_NATIVE_MODULE_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterLoadNativeModuleBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterLoadNativeModuleBody;
}

static inline uint64_t
ValidateProgramTestRunBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterProgramTestRunBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterProgramTestRunBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____PROGRAM_TEST_RUN_DATA_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterProgramTestRunBody = positionAfternone1;
        }
        else
        {
            /* Validating field ProgramHandle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterProgramTestRunBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterProgramTestRunBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterProgramTestRunBody;
                        if (hasBytes)
                        {
                            positionAfterProgramTestRunBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterProgramTestRunBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterProgramTestRunBody))
                        {
                            res = positionAfterProgramTestRunBody;
                        }
                        else
                        {
                            Err("_PROGRAM_TEST_RUN_BODY",
                                "ProgramHandle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterProgramTestRunBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterProgramTestRunBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterProgramTestRunBody0 = res;
            }
            uint64_t positionAfterProgramHandle;
            if (EverParseIsSuccess(positionAfterProgramTestRunBody0))
            {
                positionAfterProgramHandle = positionAfterProgramTestRunBody0;
            }
            else
            {
                Err("_PROGRAM_TEST_RUN_BODY",
                    "ProgramHandle",
                    EverParseErrorReasonOfResult(
                        positionAfterProgramTestRunBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterProgramHandle = positionAfterProgramTestRunBody0;
            }
            if (EverParseIsError(positionAfterProgramHandle))
            {
                positionAfterProgramTestRunBody = positionAfterProgramHandle;
            }
            else
            {
                /* Validating field RepeatCount */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                                  (InputLength - positionAfterProgramHandle);
                uint64_t positionAfterProgramTestRunBody0;
                if (!hasEnoughBytes0)
                {
                    positionAfterProgramTestRunBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterProgramHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterProgramHandle +
                        (uint64_t)(uint32_t)(uint8_t)8U;
                    uint64_t result = positionAfterProgramHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterProgramTestRunBody;
                            if (hasBytes)
                            {
                                positionAfterProgramTestRunBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterProgramTestRunBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterProgramTestRunBody))
                            {
                                res = positionAfterProgramTestRunBody;
                            }
                            else
                            {
                                Err("_PROGRAM_TEST_RUN_BODY",
                                    "RepeatCount.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterProgramTestRunBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterProgramTestRunBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterProgramTestRunBody0 = res;
                }
                uint64_t positionAfterRepeatCount;
                if (EverParseIsSuccess(positionAfterProgramTestRunBody0))
                {
                    positionAfterRepeatCount = positionAfterProgramTestRunBody0;
                }
                else
                {
                    Err("_PROGRAM_TEST_RUN_BODY",
                        "RepeatCount",
                        EverParseErrorReasonOfResult(
                            positionAfterProgramTestRunBody0),
                        Ctxt,
                        Input,
                        positionAfterProgramHandle);
                    positionAfterRepeatCount = positionAfterProgramTestRunBody0;
                }
                if (EverParseIsError(positionAfterRepeatCount))
                {
                    positionAfterProgramTestRunBody = positionAfterRepeatCount;
                }
                else
                {
                    /* Validating field Flags */
                    /* Checking that we have enough space for a UINT32, i.e., 4
                     * bytes */
                    BOOLEAN hasBytes0 =
                        (uint64_t)4U <=
                        (InputLength - positionAfterRepeatCount);
                    uint64_t positionAfterProgramTestRunBody0;
                    if (hasBytes0)
                    {
                        positionAfterProgramTestRunBody0 =
                            positionAfterRepeatCount + (uint64_t)4U;
                    }
                    else
                    {
                        positionAfterProgramTestRunBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterRepeatCount);
                    }
                    uint64_t res0;
                    if (EverParseIsSuccess(positionAfterProgramTestRunBody0))
                    {
                        res0 = positionAfterProgramTestRunBody0;
                    }
                    else
                    {
                        Err("_PROGRAM_TEST_RUN_BODY",
                            "Flags",
                            EverParseErrorReasonOfResult(
                                positionAfterProgramTestRunBody0),
                            Ctxt,
                            Input,
                            positionAfterRepeatCount);
                        res0 = positionAfterProgramTestRunBody0;
                    }
                    uint64_t positionAfterFlags = res0;
                    if (EverParseIsError(positionAfterFlags))
                    {
                        positionAfterProgramTestRunBody = positionAfterFlags;
                    }
                    else
                    {
                        /* Validating field Cpu */
                        /* Checking that we have enough space for a UINT32,
                         * i.e., 4 bytes */
                        BOOLEAN hasBytes0 =
                            (uint64_t)4U <= (InputLength - positionAfterFlags);
                        uint64_t positionAfterProgramTestRunBody0;
                        if (hasBytes0)
                        {
                            positionAfterProgramTestRunBody0 =
                                positionAfterFlags + (uint64_t)4U;
                        }
                        else
                        {
                            positionAfterProgramTestRunBody0 =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterFlags);
                        }
                        uint64_t res0;
                        if (EverParseIsSuccess(
                                positionAfterProgramTestRunBody0))
                        {
                            res0 = positionAfterProgramTestRunBody0;
                        }
                        else
                        {
                            Err("_PROGRAM_TEST_RUN_BODY",
                                "Cpu",
                                EverParseErrorReasonOfResult(
                                    positionAfterProgramTestRunBody0),
                                Ctxt,
                                Input,
                                positionAfterFlags);
                            res0 = positionAfterProgramTestRunBody0;
                        }
                        uint64_t positionAfterCpu = res0;
                        if (EverParseIsError(positionAfterCpu))
                        {
                            positionAfterProgramTestRunBody = positionAfterCpu;
                        }
                        else
                        {
                            /* Validating field BatchSize */
                            BOOLEAN
                            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                                              (InputLength - positionAfterCpu);
                            uint64_t positionAfterProgramTestRunBody0;
                            if (!hasEnoughBytes0)
                            {
                                positionAfterProgramTestRunBody0 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfterCpu);
                            }
                            else
                            {
                                uint8_t *truncatedInput = Input;
                                uint64_t truncatedInputLength =
                                    positionAfterCpu +
                                    (uint64_t)(uint32_t)(uint8_t)8U;
                                uint64_t result = positionAfterCpu;
                                while (TRUE)
                                {
                                    uint64_t position = *&result;
                                    BOOLEAN ite;
                                    if (!((uint64_t)1U <=
                                          (truncatedInputLength - position)))
                                    {
                                        ite = TRUE;
                                    }
                                    else
                                    {
                                        /* Checking that we have enough space
                                         * for a UINT8, i.e., 1 byte */
                                        BOOLEAN hasBytes =
                                            (uint64_t)1U <=
                                            (truncatedInputLength - position);
                                        uint64_t
                                            positionAfterProgramTestRunBody;
                                        if (hasBytes)
                                        {
                                            positionAfterProgramTestRunBody =
                                                position + (uint64_t)1U;
                                        }
                                        else
                                        {
                                            positionAfterProgramTestRunBody =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    position);
                                        }
                                        uint64_t res;
                                        if (EverParseIsSuccess(
                                                positionAfterProgramTestRunBody))
                                        {
                                            res =
                                                positionAfterProgramTestRunBody;
                                        }
                                        else
                                        {
                                            Err("_PROGRAM_TEST_RUN_BODY",
                                                "BatchSize.element",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterProgramTestRunBody),
                                                Ctxt,
                                                truncatedInput,
                                                position);
                                            res =
                                                positionAfterProgramTestRunBody;
                                        }
                                        uint64_t result1 = res;
                                        result = result1;
                                        ite = EverParseIsError(result1);
                                    }
                                    if (ite)
                                    {
                                        break;
                                    }
                                }
                                uint64_t res = result;
                                positionAfterProgramTestRunBody0 = res;
                            }
                            uint64_t positionAfterBatchSize;
                            if (EverParseIsSuccess(
                                    positionAfterProgramTestRunBody0))
                            {
                                positionAfterBatchSize =
                                    positionAfterProgramTestRunBody0;
                            }
                            else
                            {
                                Err("_PROGRAM_TEST_RUN_BODY",
                                    "BatchSize",
                                    EverParseErrorReasonOfResult(
                                        positionAfterProgramTestRunBody0),
                                    Ctxt,
                                    Input,
                                    positionAfterCpu);
                                positionAfterBatchSize =
                                    positionAfterProgramTestRunBody0;
                            }
                            if (EverParseIsError(positionAfterBatchSize))
                            {
                                positionAfterProgramTestRunBody =
                                    positionAfterBatchSize;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT16, i.e., 2 bytes */
                                BOOLEAN hasBytes0 =
                                    (uint64_t)2U <=
                                    (InputLength - positionAfterBatchSize);
                                uint64_t positionAfternone2;
                                if (hasBytes0)
                                {
                                    positionAfternone2 =
                                        positionAfterBatchSize + (uint64_t)2U;
                                }
                                else
                                {
                                    positionAfternone2 =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            positionAfterBatchSize);
                                }
                                uint64_t positionAfterProgramTestRunBody0;
                                if (EverParseIsError(positionAfternone2))
                                {
                                    positionAfterProgramTestRunBody0 =
                                        positionAfternone2;
                                }
                                else
                                {
                                    uint16_t r = Load16Le(
                                        Input +
                                        (uint32_t)positionAfterBatchSize);
                                    uint16_t none1 = (uint16_t)(uint32_t)r;
                                    BOOLEAN
                                    noneConstraintIsOk1 =
                                        none1 <=
                                        (MessageLength -
                                         (uint16_t)
                                             EBPFPROTOCOL____PROGRAM_TEST_RUN_DATA_OFFSET);
                                    uint64_t positionAfternone3 =
                                        EverParseCheckConstraintOk(
                                            noneConstraintIsOk1,
                                            positionAfternone2);
                                    if (EverParseIsError(positionAfternone3))
                                    {
                                        positionAfterProgramTestRunBody0 =
                                            positionAfternone3;
                                    }
                                    else
                                    {
                                        /* Validating field Data */
                                        BOOLEAN
                                        hasEnoughBytes =
                                            (uint64_t)(uint32_t)(
                                                MessageLength -
                                                (uint16_t)
                                                    EBPFPROTOCOL____PROGRAM_TEST_RUN_DATA_OFFSET) <=
                                            (InputLength - positionAfternone3);
                                        uint64_t
                                            positionAfterProgramTestRunBody;
                                        if (!hasEnoughBytes)
                                        {
                                            positionAfterProgramTestRunBody =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    positionAfternone3);
                                        }
                                        else
                                        {
                                            uint8_t *truncatedInput = Input;
                                            uint64_t truncatedInputLength =
                                                positionAfternone3 +
                                                (uint64_t)(uint32_t)(
                                                    MessageLength -
                                                    (uint16_t)
                                                        EBPFPROTOCOL____PROGRAM_TEST_RUN_DATA_OFFSET);
                                            uint64_t result =
                                                positionAfternone3;
                                            while (TRUE)
                                            {
                                                uint64_t position = *&result;
                                                BOOLEAN ite;
                                                if (!((uint64_t)1U <=
                                                      (truncatedInputLength -
                                                       position)))
                                                {
                                                    ite = TRUE;
                                                }
                                                else
                                                {
                                                    /* Checking that we have
                                                     * enough space for a UINT8,
                                                     * i.e., 1 byte */
                                                    BOOLEAN hasBytes =
                                                        (uint64_t)1U <=
                                                        (truncatedInputLength -
                                                         position);
                                                    uint64_t
                                                        positionAfterProgramTestRunBody;
                                                    if (hasBytes)
                                                    {
                                                        positionAfterProgramTestRunBody =
                                                            position +
                                                            (uint64_t)1U;
                                                    }
                                                    else
                                                    {
                                                        positionAfterProgramTestRunBody =
                                                            EverParseSetValidatorErrorPos(
                                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                position);
                                                    }
                                                    uint64_t res;
                                                    if (EverParseIsSuccess(
                                                            positionAfterProgramTestRunBody))
                                                    {
                                                        res =
                                                            positionAfterProgramTestRunBody;
                                                    }
                                                    else
                                                    {
                                                        Err("_PROGRAM_TEST_RUN_"
                                                            "BODY",
                                                            "Data.element",
                                                            EverParseErrorReasonOfResult(
                                                                positionAfterProgramTestRunBody),
                                                            Ctxt,
                                                            truncatedInput,
                                                            position);
                                                        res =
                                                            positionAfterProgramTestRunBody;
                                                    }
                                                    uint64_t result1 = res;
                                                    result = result1;
                                                    ite = EverParseIsError(
                                                        result1);
                                                }
                                                if (ite)
                                                {
                                                    break;
                                                }
                                            }
                                            uint64_t res = result;
                                            positionAfterProgramTestRunBody =
                                                res;
                                        }
                                        if (EverParseIsSuccess(
                                                positionAfterProgramTestRunBody))
                                        {
                                            positionAfterProgramTestRunBody0 =
                                                positionAfterProgramTestRunBody;
                                        }
                                        else
                                        {
                                            Err("_PROGRAM_TEST_RUN_BODY",
                                                "Data",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterProgramTestRunBody),
                                                Ctxt,
                                                Input,
                                                positionAfternone3);
                                            positionAfterProgramTestRunBody0 =
                                                positionAfterProgramTestRunBody;
                                        }
                                    }
                                }
                                if (EverParseIsSuccess(
                                        positionAfterProgramTestRunBody0))
                                {
                                    positionAfterProgramTestRunBody =
                                        positionAfterProgramTestRunBody0;
                                }
                                else
                                {
                                    Err("_PROGRAM_TEST_RUN_BODY",
                                        "none",
                                        EverParseErrorReasonOfResult(
                                            positionAfterProgramTestRunBody0),
                                        Ctxt,
                                        Input,
                                        positionAfterBatchSize);
                                    positionAfterProgramTestRunBody =
                                        positionAfterProgramTestRunBody0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterProgramTestRunBody))
    {
        return positionAfterProgramTestRunBody;
    }
    Err("_PROGRAM_TEST_RUN_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterProgramTestRunBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterProgramTestRunBody;
}

static inline uint64_t
ValidatePinnedObjectPathBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterPinnedObjectPathBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterPinnedObjectPathBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____PINNED_OBJECT_PATH_START_PATH_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterPinnedObjectPathBody = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes0 =
                (uint64_t)4U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0)
            {
                positionAfternone2 = positionAfternone1 + (uint64_t)4U;
            }
            else
            {
                positionAfternone2 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterPinnedObjectPathBody0;
            if (EverParseIsError(positionAfternone2))
            {
                positionAfterPinnedObjectPathBody0 = positionAfternone2;
            }
            else
            {
                uint32_t none1 = Load32Le(Input + (uint32_t)positionAfternone1);
                BOOLEAN noneConstraintIsOk1 =
                    none1 <= (uint32_t)EBPFPROTOCOL____EBPF_OBJECT_TYPE_MAX;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                    noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3))
                {
                    positionAfterPinnedObjectPathBody0 = positionAfternone3;
                }
                else
                {
                    /* Validating field StartPath */
                    BOOLEAN
                    hasEnoughBytes =
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____PINNED_OBJECT_PATH_START_PATH_OFFSET) <=
                        (InputLength - positionAfternone3);
                    uint64_t positionAfterPinnedObjectPathBody;
                    if (!hasEnoughBytes)
                    {
                        positionAfterPinnedObjectPathBody =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfternone3);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfternone3 +
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____PINNED_OBJECT_PATH_START_PATH_OFFSET);
                        uint64_t result = positionAfternone3;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterPinnedObjectPathBody;
                                if (hasBytes)
                                {
                                    positionAfterPinnedObjectPathBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterPinnedObjectPathBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterPinnedObjectPathBody))
                                {
                                    res = positionAfterPinnedObjectPathBody;
                                }
                                else
                                {
                                    Err("_PINNED_OBJECT_PATH_BODY",
                                        "StartPath.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterPinnedObjectPathBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res = positionAfterPinnedObjectPathBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterPinnedObjectPathBody = res;
                    }
                    if (EverParseIsSuccess(positionAfterPinnedObjectPathBody))
                    {
                        positionAfterPinnedObjectPathBody0 =
                            positionAfterPinnedObjectPathBody;
                    }
                    else
                    {
                        Err("_PINNED_OBJECT_PATH_BODY",
                            "StartPath",
                            EverParseErrorReasonOfResult(
                                positionAfterPinnedObjectPathBody),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        positionAfterPinnedObjectPathBody0 =
                            positionAfterPinnedObjectPathBody;
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterPinnedObjectPathBody0))
            {
                positionAfterPinnedObjectPathBody =
                    positionAfterPinnedObjectPathBody0;
            }
            else
            {
                Err("_PINNED_OBJECT_PATH_BODY",
                    "none",
                    EverParseErrorReasonOfResult(
                        positionAfterPinnedObjectPathBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterPinnedObjectPathBody =
                    positionAfterPinnedObjectPathBody0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterPinnedObjectPathBody))
    {
        return positionAfterPinnedObjectPathBody;
    }
    Err("_PINNED_OBJECT_PATH_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterPinnedObjectPathBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterPinnedObjectPathBody;
}

static inline uint64_t
ValidateMapDeleteElementBatchBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapDeleteElementBatchBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapDeleteElementBatchBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____DELETE_ELEMENT_BATCH_KEYS_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapDeleteElementBatchBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapDeleteElementBatchBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapDeleteElementBatchBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapDeleteElementBatchBody;
                        if (hasBytes)
                        {
                            positionAfterMapDeleteElementBatchBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapDeleteElementBatchBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(
                                positionAfterMapDeleteElementBatchBody))
                        {
                            res = positionAfterMapDeleteElementBatchBody;
                        }
                        else
                        {
                            Err("_MAP_DELETE_ELEMENT_BATCH_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapDeleteElementBatchBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapDeleteElementBatchBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapDeleteElementBatchBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterMapDeleteElementBatchBody0))
            {
                positionAfterHandle = positionAfterMapDeleteElementBatchBody0;
            }
            else
            {
                Err("_MAP_DELETE_ELEMENT_BATCH_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapDeleteElementBatchBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterMapDeleteElementBatchBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterMapDeleteElementBatchBody = positionAfterHandle;
            }
            else
            {
                /* Validating field Keys */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)(uint32_t)(
                        MessageLength -
                        (uint16_t)
                            EBPFPROTOCOL____DELETE_ELEMENT_BATCH_KEYS_OFFSET) <=
                    (InputLength - positionAfterHandle);
                uint64_t positionAfterMapDeleteElementBatchBody0;
                if (!hasEnoughBytes)
                {
                    positionAfterMapDeleteElementBatchBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterHandle);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterHandle +
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____DELETE_ELEMENT_BATCH_KEYS_OFFSET);
                    uint64_t result = positionAfterHandle;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMapDeleteElementBatchBody;
                            if (hasBytes)
                            {
                                positionAfterMapDeleteElementBatchBody =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMapDeleteElementBatchBody =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterMapDeleteElementBatchBody))
                            {
                                res = positionAfterMapDeleteElementBatchBody;
                            }
                            else
                            {
                                Err("_MAP_DELETE_ELEMENT_BATCH_BODY",
                                    "Keys.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMapDeleteElementBatchBody),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterMapDeleteElementBatchBody;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterMapDeleteElementBatchBody0 = res;
                }
                if (EverParseIsSuccess(positionAfterMapDeleteElementBatchBody0))
                {
                    positionAfterMapDeleteElementBatchBody =
                        positionAfterMapDeleteElementBatchBody0;
                }
                else
                {
                    Err("_MAP_DELETE_ELEMENT_BATCH_BODY",
                        "Keys",
                        EverParseErrorReasonOfResult(
                            positionAfterMapDeleteElementBatchBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    positionAfterMapDeleteElementBatchBody =
                        positionAfterMapDeleteElementBatchBody0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapDeleteElementBatchBody))
    {
        return positionAfterMapDeleteElementBatchBody;
    }
    Err("_MAP_DELETE_ELEMENT_BATCH_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapDeleteElementBatchBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapDeleteElementBatchBody;
}

static inline uint64_t
ValidateMapGetNextKeyValueBatchBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterMapGetNextKeyValueBatchBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterMapGetNextKeyValueBatchBody = positionAfternone;
    }
    else
    {
        BOOLEAN
        noneConstraintIsOk =
            MessageLength >=
            (uint16_t)EBPFPROTOCOL____GET_NEXT_KEY_VALUE_BATCH_KEY_OFFSET;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterMapGetNextKeyValueBatchBody = positionAfternone1;
        }
        else
        {
            /* Validating field Handle */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)8U <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterMapGetNextKeyValueBatchBody0;
            if (!hasEnoughBytes0)
            {
                positionAfterMapGetNextKeyValueBatchBody0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 + (uint64_t)(uint32_t)(uint8_t)8U;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMapGetNextKeyValueBatchBody;
                        if (hasBytes)
                        {
                            positionAfterMapGetNextKeyValueBatchBody =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMapGetNextKeyValueBatchBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(
                                positionAfterMapGetNextKeyValueBatchBody))
                        {
                            res = positionAfterMapGetNextKeyValueBatchBody;
                        }
                        else
                        {
                            Err("_MAP_GET_NEXT_KEY_VALUE_BATCH_BODY",
                                "Handle.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMapGetNextKeyValueBatchBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterMapGetNextKeyValueBatchBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterMapGetNextKeyValueBatchBody0 = res;
            }
            uint64_t positionAfterHandle;
            if (EverParseIsSuccess(positionAfterMapGetNextKeyValueBatchBody0))
            {
                positionAfterHandle = positionAfterMapGetNextKeyValueBatchBody0;
            }
            else
            {
                Err("_MAP_GET_NEXT_KEY_VALUE_BATCH_BODY",
                    "Handle",
                    EverParseErrorReasonOfResult(
                        positionAfterMapGetNextKeyValueBatchBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHandle = positionAfterMapGetNextKeyValueBatchBody0;
            }
            if (EverParseIsError(positionAfterHandle))
            {
                positionAfterMapGetNextKeyValueBatchBody = positionAfterHandle;
            }
            else
            {
                /* Validating field FindAndDelete */
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes0 =
                    (uint64_t)1U <= (InputLength - positionAfterHandle);
                uint64_t positionAfterMapGetNextKeyValueBatchBody0;
                if (hasBytes0)
                {
                    positionAfterMapGetNextKeyValueBatchBody0 =
                        positionAfterHandle + (uint64_t)1U;
                }
                else
                {
                    positionAfterMapGetNextKeyValueBatchBody0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterHandle);
                }
                uint64_t res0;
                if (EverParseIsSuccess(
                        positionAfterMapGetNextKeyValueBatchBody0))
                {
                    res0 = positionAfterMapGetNextKeyValueBatchBody0;
                }
                else
                {
                    Err("_MAP_GET_NEXT_KEY_VALUE_BATCH_BODY",
                        "FindAndDelete",
                        EverParseErrorReasonOfResult(
                            positionAfterMapGetNextKeyValueBatchBody0),
                        Ctxt,
                        Input,
                        positionAfterHandle);
                    res0 = positionAfterMapGetNextKeyValueBatchBody0;
                }
                uint64_t positionAfterFindAndDelete = res0;
                if (EverParseIsError(positionAfterFindAndDelete))
                {
                    positionAfterMapGetNextKeyValueBatchBody =
                        positionAfterFindAndDelete;
                }
                else
                {
                    /* Validating field PreviousKey */
                    BOOLEAN
                    hasEnoughBytes =
                        (uint64_t)(uint32_t)(
                            MessageLength -
                            (uint16_t)
                                EBPFPROTOCOL____GET_NEXT_KEY_VALUE_BATCH_KEY_OFFSET) <=
                        (InputLength - positionAfterFindAndDelete);
                    uint64_t positionAfterMapGetNextKeyValueBatchBody0;
                    if (!hasEnoughBytes)
                    {
                        positionAfterMapGetNextKeyValueBatchBody0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterFindAndDelete);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterFindAndDelete +
                            (uint64_t)(uint32_t)(
                                MessageLength -
                                (uint16_t)
                                    EBPFPROTOCOL____GET_NEXT_KEY_VALUE_BATCH_KEY_OFFSET);
                        uint64_t result = positionAfterFindAndDelete;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t
                                    positionAfterMapGetNextKeyValueBatchBody;
                                if (hasBytes)
                                {
                                    positionAfterMapGetNextKeyValueBatchBody =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterMapGetNextKeyValueBatchBody =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res;
                                if (EverParseIsSuccess(
                                        positionAfterMapGetNextKeyValueBatchBody))
                                {
                                    res =
                                        positionAfterMapGetNextKeyValueBatchBody;
                                }
                                else
                                {
                                    Err("_MAP_GET_NEXT_KEY_VALUE_BATCH_BODY",
                                        "PreviousKey.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterMapGetNextKeyValueBatchBody),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res =
                                        positionAfterMapGetNextKeyValueBatchBody;
                                }
                                uint64_t result1 = res;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res = result;
                        positionAfterMapGetNextKeyValueBatchBody0 = res;
                    }
                    if (EverParseIsSuccess(
                            positionAfterMapGetNextKeyValueBatchBody0))
                    {
                        positionAfterMapGetNextKeyValueBatchBody =
                            positionAfterMapGetNextKeyValueBatchBody0;
                    }
                    else
                    {
                        Err("_MAP_GET_NEXT_KEY_VALUE_BATCH_BODY",
                            "PreviousKey",
                            EverParseErrorReasonOfResult(
                                positionAfterMapGetNextKeyValueBatchBody0),
                            Ctxt,
                            Input,
                            positionAfterFindAndDelete);
                        positionAfterMapGetNextKeyValueBatchBody =
                            positionAfterMapGetNextKeyValueBatchBody0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMapGetNextKeyValueBatchBody))
    {
        return positionAfterMapGetNextKeyValueBatchBody;
    }
    Err("_MAP_GET_NEXT_KEY_VALUE_BATCH_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterMapGetNextKeyValueBatchBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterMapGetNextKeyValueBatchBody;
}

static inline uint64_t
ValidateGenericBody(
    uint16_t MessageLength,
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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterGenericBody;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterGenericBody = positionAfternone;
    }
    else
    {
        BOOLEAN noneConstraintIsOk =
            MessageLength >= (uint16_t)EBPFPROTOCOL____HEADER_SIZE;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterGenericBody = positionAfternone1;
        }
        else
        {
            /* Validating field Rest */
            BOOLEAN
            hasEnoughBytes =
                (uint64_t)(uint32_t)(
                    MessageLength - (uint16_t)EBPFPROTOCOL____HEADER_SIZE) <=
                (InputLength - positionAfternone1);
            uint64_t positionAfterGenericBody0;
            if (!hasEnoughBytes)
            {
                positionAfterGenericBody0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 +
                    (uint64_t)(uint32_t)(
                        MessageLength - (uint16_t)EBPFPROTOCOL____HEADER_SIZE);
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterGenericBody;
                        if (hasBytes)
                        {
                            positionAfterGenericBody = position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterGenericBody =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterGenericBody))
                        {
                            res = positionAfterGenericBody;
                        }
                        else
                        {
                            Err("_GENERIC_BODY",
                                "Rest.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterGenericBody),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterGenericBody;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterGenericBody0 = res;
            }
            if (EverParseIsSuccess(positionAfterGenericBody0))
            {
                positionAfterGenericBody = positionAfterGenericBody0;
            }
            else
            {
                Err("_GENERIC_BODY",
                    "Rest",
                    EverParseErrorReasonOfResult(positionAfterGenericBody0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterGenericBody = positionAfterGenericBody0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterGenericBody))
    {
        return positionAfterGenericBody;
    }
    Err("_GENERIC_BODY",
        "none",
        EverParseErrorReasonOfResult(positionAfterGenericBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterGenericBody;
}

static inline uint64_t
ValidateOperationBody(
    uint32_t Id,
    uint16_t MessageLength,
    uint8_t *Ctxt,
    void (*Err)(
        EverParseString x0,
        EverParseString x1,
        EverParseString x2,
        uint8_t *x3,
        uint8_t *x4,
        uint64_t x5),
    uint8_t *Input,
    uint64_t InputLen,
    uint64_t StartPosition)
{
    if (Id == (uint32_t)EBPFPROTOCOL____OP_CREATE_PROGRAM)
    {
        /* Validating field CreateProgram */
        uint64_t positionAfterOperationBody = ValidateCreateProgramBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_CREATE_MAP)
    {
        /* Validating field CreateMap */
        uint64_t positionAfterOperationBody = ValidateCreateMapBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_LOAD_CODE)
    {
        /* Validating field LoadCode */
        uint64_t positionAfterOperationBody = ValidateLoadCodeBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_FIND_ELEMENT)
    {
        /* Validating field MapFindElement */
        uint64_t positionAfterOperationBody = ValidateMapFindElementBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_UPDATE_ELEMENT)
    {
        /* Validating field MapUpdate */
        uint64_t positionAfterOperationBody = ValidateMapUpdateBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_UPDATE_ELEMENT_WITH_HANDLE)
    {
        /* Validating field MapUpdateWithHandle */
        uint64_t positionAfterOperationBody = ValidateMapUpdateWithHandleBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_DELETE_ELEMENT)
    {
        /* Validating field MapDeleteElement */
        uint64_t positionAfterOperationBody = ValidateMapDeleteElementBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_GET_NEXT_KEY)
    {
        /* Validating field MapGetNextKey */
        uint64_t positionAfterOperationBody = ValidateMapGetNextKeyBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_UPDATE_PINNING)
    {
        /* Validating field UpdatePinning */
        uint64_t positionAfterOperationBody = ValidateUpdatePinningBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_GET_PINNED_OBJECT)
    {
        /* Validating field GetPinnedObject */
        uint64_t positionAfterOperationBody = ValidateGetPinnedObjectBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_LINK_PROGRAM)
    {
        /* Validating field LinkProgram */
        uint64_t positionAfterOperationBody = ValidateLinkProgramBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_UNLINK_PROGRAM)
    {
        /* Validating field UnlinkProgram */
        uint64_t positionAfterOperationBody = ValidateUnlinkProgramBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_WRITE_DATA)
    {
        /* Validating field MapWriteData */
        uint64_t positionAfterOperationBody = ValidateMapWriteDataBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_LOAD_NATIVE_MODULE)
    {
        /* Validating field LoadNativeModule */
        uint64_t positionAfterOperationBody = ValidateLoadNativeModuleBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_PROGRAM_TEST_RUN)
    {
        /* Validating field ProgramTestRun */
        uint64_t positionAfterOperationBody = ValidateProgramTestRunBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_UPDATE_ELEMENT_BATCH)
    {
        /* Validating field MapUpdateBatch */
        uint64_t positionAfterOperationBody = ValidateMapUpdateBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_DELETE_ELEMENT_BATCH)
    {
        /* Validating field MapDeleteElementBatch */
        uint64_t positionAfterOperationBody = ValidateMapDeleteElementBatchBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_MAP_GET_NEXT_KEY_VALUE_BATCH)
    {
        /* Validating field MapGetNextKeyValueBatch */
        uint64_t positionAfterOperationBody =
            ValidateMapGetNextKeyValueBatchBody(
                MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    if (Id == (uint32_t)EBPFPROTOCOL____OP_GET_NEXT_PINNED_OBJECT_PATH)
    {
        /* Validating field PinnedObjectPath */
        uint64_t positionAfterOperationBody = ValidatePinnedObjectPathBody(
            MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterOperationBody))
        {
            return positionAfterOperationBody;
        }
        Err("_OPERATION_BODY",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOperationBody),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOperationBody;
    }
    /* Validating field Generic */
    uint64_t positionAfterOperationBody = ValidateGenericBody(
        MessageLength, Ctxt, Err, Input, InputLen, StartPosition);
    if (EverParseIsSuccess(positionAfterOperationBody))
    {
        return positionAfterOperationBody;
    }
    Err("_OPERATION_BODY",
        "missing",
        EverParseErrorReasonOfResult(positionAfterOperationBody),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterOperationBody;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes0 = (uint64_t)2U <= (InputLength - StartPosition);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = StartPosition + (uint64_t)2U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterEbpfIoctlMessage;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterEbpfIoctlMessage = positionAfternone;
    }
    else
    {
        uint16_t r = Load16Le(Input + (uint32_t)StartPosition);
        uint16_t none = (uint16_t)(uint32_t)r;
        BOOLEAN
        noneConstraintIsOk = none >= (uint16_t)EBPFPROTOCOL____HEADER_SIZE &&
                             (uint32_t)none <= BufferLength;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterEbpfIoctlMessage = positionAfternone1;
        }
        else
        {
            /* Padding between uint16_t length and 4-byte-aligned enum id */
            BOOLEAN
            hasEnoughBytes =
                (uint64_t)(uint32_t)EBPFPROTOCOL____HEADER_PAD_SIZE <=
                (InputLength - positionAfternone1);
            uint64_t positionAfterEbpfIoctlMessage0;
            if (!hasEnoughBytes)
            {
                positionAfterEbpfIoctlMessage0 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 +
                    (uint64_t)(uint32_t)EBPFPROTOCOL____HEADER_PAD_SIZE;
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterEbpfIoctlMessage;
                        if (hasBytes)
                        {
                            positionAfterEbpfIoctlMessage =
                                position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterEbpfIoctlMessage =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterEbpfIoctlMessage))
                        {
                            res = positionAfterEbpfIoctlMessage;
                        }
                        else
                        {
                            Err("_EBPF_IOCTL_MESSAGE",
                                "HeaderPad.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterEbpfIoctlMessage),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterEbpfIoctlMessage;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterEbpfIoctlMessage0 = res;
            }
            uint64_t positionAfterHeaderPad;
            if (EverParseIsSuccess(positionAfterEbpfIoctlMessage0))
            {
                positionAfterHeaderPad = positionAfterEbpfIoctlMessage0;
            }
            else
            {
                Err("_EBPF_IOCTL_MESSAGE",
                    "HeaderPad",
                    EverParseErrorReasonOfResult(
                        positionAfterEbpfIoctlMessage0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterHeaderPad = positionAfterEbpfIoctlMessage0;
            }
            if (EverParseIsError(positionAfterHeaderPad))
            {
                positionAfterEbpfIoctlMessage = positionAfterHeaderPad;
            }
            else
            {
                /* Checking that we have enough space for a UINT32, i.e., 4
                 * bytes */
                BOOLEAN hasBytes =
                    (uint64_t)4U <= (InputLength - positionAfterHeaderPad);
                uint64_t positionAfternone2;
                if (hasBytes)
                {
                    positionAfternone2 = positionAfterHeaderPad + (uint64_t)4U;
                }
                else
                {
                    positionAfternone2 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterHeaderPad);
                }
                uint64_t positionAfterEbpfIoctlMessage0;
                if (EverParseIsError(positionAfternone2))
                {
                    positionAfterEbpfIoctlMessage0 = positionAfternone2;
                }
                else
                {
                    uint32_t none1 =
                        Load32Le(Input + (uint32_t)positionAfterHeaderPad);
                    BOOLEAN noneConstraintIsOk1 =
                        none1 <= (uint32_t)EBPFPROTOCOL____MAX_OPERATION_ID;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                        noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3))
                    {
                        positionAfterEbpfIoctlMessage0 = positionAfternone3;
                    }
                    else
                    {
                        /* Operation-specific body */
                        uint64_t positionAfterEbpfIoctlMessage =
                            ValidateOperationBody(
                                none1,
                                none,
                                Ctxt,
                                Err,
                                Input,
                                InputLength,
                                positionAfternone3);
                        if (EverParseIsSuccess(positionAfterEbpfIoctlMessage))
                        {
                            positionAfterEbpfIoctlMessage0 =
                                positionAfterEbpfIoctlMessage;
                        }
                        else
                        {
                            Err("_EBPF_IOCTL_MESSAGE",
                                "Body",
                                EverParseErrorReasonOfResult(
                                    positionAfterEbpfIoctlMessage),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            positionAfterEbpfIoctlMessage0 =
                                positionAfterEbpfIoctlMessage;
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterEbpfIoctlMessage0))
                {
                    positionAfterEbpfIoctlMessage =
                        positionAfterEbpfIoctlMessage0;
                }
                else
                {
                    Err("_EBPF_IOCTL_MESSAGE",
                        "none",
                        EverParseErrorReasonOfResult(
                            positionAfterEbpfIoctlMessage0),
                        Ctxt,
                        Input,
                        positionAfterHeaderPad);
                    positionAfterEbpfIoctlMessage =
                        positionAfterEbpfIoctlMessage0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterEbpfIoctlMessage))
    {
        return positionAfterEbpfIoctlMessage;
    }
    Err("_EBPF_IOCTL_MESSAGE",
        "none",
        EverParseErrorReasonOfResult(positionAfterEbpfIoctlMessage),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterEbpfIoctlMessage;
}
