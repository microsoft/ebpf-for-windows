#include "ElfWrapper.h"
#include "EverParse.h"
#include "Elf.h"
void
ElfEverParseError(const char* StructName, const char* FieldName, const char* Reason);

static void
DefaultErrorHandler(
    const char* typename_s,
    const char* fieldname,
    const char* reason,
    uint8_t* context,
    EverParseInputBuffer input,
    uint64_t start_pos)
{
    EverParseErrorFrame* frame = (EverParseErrorFrame*)context;
    EverParseDefaultErrorHandler(typename_s, fieldname, reason, frame, input, start_pos);
}

BOOLEAN
ElfCheckElf(uint64_t ___ElfFileSize, uint8_t* base, uint32_t len)
{
    EverParseErrorFrame frame;
    frame.filled = FALSE;
    uint64_t result = ElfValidateElf(___ElfFileSize, (uint8_t*)&frame, &DefaultErrorHandler, base, len, 0);
    if (EverParseIsError(result)) {
        if (frame.filled) {
            ElfEverParseError(frame.typename_s, frame.fieldname, frame.reason);
        }
        return FALSE;
    }
    return TRUE;
}
