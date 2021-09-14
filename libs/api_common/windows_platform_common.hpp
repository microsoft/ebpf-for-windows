// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

EbpfHelperPrototype
get_helper_prototype_windows(int32_t n);

bool
is_helper_usable_windows(int32_t n);

EbpfProgramType
get_program_type_windows(const GUID& program_type);

EbpfMapType
get_map_type_windows(uint32_t platform_specific_type);

EbpfProgramType
get_program_type_windows(const GUID& program_type);

EbpfProgramType
get_program_type_windows(const std::string& section, const std::string& path);

EbpfMapDescriptor&
get_map_descriptor_windows(int map_fd);

const ebpf_attach_type_t*
get_attach_type_windows(const std::string& section);
