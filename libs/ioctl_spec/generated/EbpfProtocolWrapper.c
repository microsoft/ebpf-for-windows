#include "EbpfProtocolWrapper.h"
#include "EverParse.h"
#include "EbpfProtocol.h"
void
EbpfProtocolEverParseError(
    const char *StructName,
    const char *FieldName,
    const char *Reason);

static void
DefaultErrorHandler(
    const char *typename_s,
    const char *fieldname,
    const char *reason,
    uint8_t *context,
    EverParseInputBuffer input,
    uint64_t start_pos)
{
    EverParseErrorFrame *frame = (EverParseErrorFrame *)context;
    EverParseDefaultErrorHandler(
        typename_s, fieldname, reason, frame, input, start_pos);
}

BOOLEAN
EbpfProtocolCheckEbpfIoctlMessage(
    uint32_t ___BufferLength,
    uint8_t *base,
    uint32_t len)
{
    EverParseErrorFrame frame;
    frame.filled = FALSE;
    uint64_t result = EbpfProtocolValidateEbpfIoctlMessage(
        ___BufferLength, (uint8_t *)&frame, &DefaultErrorHandler, base, len, 0);
    if (EverParseIsError(result))
    {
        if (frame.filled)
        {
            EbpfProtocolEverParseError(
                frame.typename_s, frame.fieldname, frame.reason);
        }
        return FALSE;
    }
    return TRUE;
}
