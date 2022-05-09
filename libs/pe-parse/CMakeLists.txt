# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("pe_parse" STATIC
  ../../external/pe-parse/pe-parser-library/include/pe-parse/nt-headers.h
  ../../external/pe-parse/pe-parser-library/include/pe-parse/parse.h
  ../../external/pe-parse/pe-parser-library/include/pe-parse/to_string.h
  ../../external/pe-parse/pe-parser-library/src/buffer.cpp
  ../../external/pe-parse/pe-parser-library/src/parse.cpp
  ../../external/pe-parse/pe-parser-library/src/unicode_winapi.cpp
)

target_include_directories("pe_parse" PRIVATE
  "${CMAKE_SOURCE_DIR}/external/pe-parse/pe-parser-library/include"
)

target_compile_options("pe_parse" PRIVATE
  /w
)
