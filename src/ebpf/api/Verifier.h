#pragma once

#ifdef __cplusplus
extern "C" {
#endif
    int get_file_size(char* filename, size_t* byte_code_size);
    int verify(const char* filename, const char* sectionname, uint8_t* byte_code, size_t* byte_code_size, char** error_message);
    int verify_byte_code(const char* path, const char* section_name, const uint8_t* byte_code, size_t byte_code_size, char** error_message);
#ifdef __cplusplus
}
#endif