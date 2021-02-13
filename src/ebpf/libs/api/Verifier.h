#pragma once

#ifdef __cplusplus
extern "C" {
#endif
    typedef int (*map_create_fp)(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, uint32_t options);
    int get_file_size(char* filename, size_t* byte_code_size);
    int verify(const char* filename, const char* sectionname, uint8_t* byte_code, size_t* byte_code_size, map_create_fp map_creat_function, char** error_message);
    int verify_byte_code(const char* path, const char* section_name, const uint8_t* byte_code, size_t byte_code_size, char** error_message);
#ifdef __cplusplus
}
#endif