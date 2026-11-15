// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS

#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "ebpf_core.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_namespace.h"
#include "ebpf_native.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "execution_context_unit_test_jit.h"
#include "helpers.h"
#include "user\ebpf_native_test.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>

namespace {
const GUID namespace_a = {0x34b032b1, 0x564a, 0x40e1, {1, 3, 5, 7, 2, 4, 6, 8}};
const GUID namespace_b = {0x34b032b2, 0x564a, 0x40e1, {1, 3, 5, 7, 2, 4, 6, 8}};
const GUID native_npi = {0xc847aac8, 0xa6f2, 0x4b53, {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};
const std::array<const char*, 3> map_names = {"ns_reuse", "ns_created", "ns_progarr"};
const std::array<const char*, 3> pin_paths = {"BPF:\\ns_reuse", "BPF:\\ns_created", "BPF:\\ns_progarr"};

class native_epoch
{
  public:
    native_epoch() { ebpf_epoch_enter(&state); }
    ~native_epoch() { ebpf_epoch_exit(&state); }

  private:
    ebpf_epoch_state_t state{};
};

class native_handle
{
  public:
    ~native_handle() { close(); }
    void
    close()
    {
        if (value != ebpf_handle_invalid) {
            CHECK(ebpf_handle_close(value) == EBPF_SUCCESS);
            value = ebpf_handle_invalid;
        }
    }
    ebpf_handle_t value = ebpf_handle_invalid;
};

using object_ptr = std::unique_ptr<ebpf_core_object_t, ebpf_object_deleter<ebpf_core_object_t>>;

object_ptr
reference_object(ebpf_handle_t handle, ebpf_object_type_t type)
{
    ebpf_core_object_t* object = nullptr;
    REQUIRE(EBPF_OBJECT_REFERENCE_BY_HANDLE(handle, type, &object) == EBPF_SUCCESS);
    return object_ptr(object);
}

cxplat_utf8_string_t
pin_path(size_t index)
{
    auto text = pin_paths[index];
    return {reinterpret_cast<uint8_t*>(const_cast<char*>(text)), strlen(text)};
}

uint64_t
native_entry(void*, const program_runtime_context_t*)
{
    return 42;
}

void
native_version(bpf2c_version_t* version)
{
    *version = {1, 4, 0};
}

void
native_maps(map_entry_t** output, size_t* count)
{
    static std::array<map_entry_t, 3> maps = []() {
        std::array<map_entry_t, 3> entries{};
        for (size_t index = 0; index < entries.size(); index++) {
            entries[index].header = EBPF_NATIVE_MAP_ENTRY_HEADER;
            entries[index].name = map_names[index];
            entries[index].definition.type = index == 2 ? BPF_MAP_TYPE_PROG_ARRAY : BPF_MAP_TYPE_ARRAY;
            entries[index].definition.key_size = sizeof(uint32_t);
            entries[index].definition.value_size = sizeof(uint32_t);
            entries[index].definition.max_entries = index == 2 ? 2 : 1;
            entries[index].definition.pinning = LIBBPF_PIN_BY_NAME;
        }
        return entries;
    }();
    *output = maps.data();
    *count = maps.size();
}

void
native_programs(program_entry_t** output, size_t* count)
{
    static uint16_t indices[] = {0, 1, 2};
    static std::array<program_entry_t, 2> programs = []() {
        std::array<program_entry_t, 2> entries{};
        for (size_t index = 0; index < entries.size(); index++) {
            entries[index].header = EBPF_NATIVE_PROGRAM_ENTRY_HEADER;
            entries[index].function = native_entry;
            entries[index].pe_section_name = "sample_ext";
            entries[index].section_name = "sample_ext";
            entries[index].program_name = index == 0 ? "ns_first" : "ns_second";
            entries[index].referenced_map_indices = indices;
            entries[index].referenced_map_count = static_cast<uint16_t>(std::size(indices));
            entries[index].bpf_instruction_count = 2;
            entries[index].program_type = const_cast<ebpf_program_type_t*>(&EBPF_PROGRAM_TYPE_SAMPLE);
            entries[index].expected_attach_type = const_cast<ebpf_attach_type_t*>(&EBPF_ATTACH_TYPE_SAMPLE);
            entries[index].program_info_hash_type = "";
        }
        return entries;
    }();
    *output = programs.data();
    *count = programs.size();
}

void
native_initial_values(map_initial_values_t** output, size_t* count)
{
    static const char* values[] = {"ns_first", "ns_second"};
    static map_initial_values_t initial = {
        EBPF_NATIVE_MAP_INITIAL_VALUES_HEADER, "ns_progarr", std::size(values), values};
    *output = &initial;
    *count = 1;
}

void
native_hash(const uint8_t** output, size_t* count)
{
    *output = nullptr;
    *count = 0;
}

void
native_globals(global_variable_section_info_t** output, size_t* count)
{
    *output = nullptr;
    *count = 0;
}

const metadata_table_t metadata = {
    sizeof(metadata_table_t),
    native_programs,
    native_maps,
    native_hash,
    native_version,
    native_initial_values,
    native_globals};

class native_registration
{
  public:
    ~native_registration()
    {
        if (handle != nullptr) {
            auto status = NmrDeregisterClient(handle);
            if (status == STATUS_PENDING) {
                NmrWaitForClientDeregisterComplete(handle);
            } else {
                CHECK(status == STATUS_SUCCESS);
            }
        }
    }
    HANDLE handle = nullptr;
};

class native_module
{
  public:
    native_module()
    {
        REQUIRE(ebpf_guid_create(&id.Guid) == EBPF_SUCCESS);
        cxplat_utf8_string_t path{};
        REQUIRE(
            cxplat_get_module_path_from_address(reinterpret_cast<void*>(native_version), &path) ==
            CXPLAT_STATUS_SUCCESS);
        std::array<uint8_t, 32> hash{};
        cxplat_utf8_string_t algorithm = CXPLAT_UTF8_STRING_FROM_CONST_STRING("SHA256");
        size_t hash_length = 0;
        auto hash_result = ebpf_hash_file_contents(&path, &algorithm, hash.data(), hash.size(), &hash_length);
        cxplat_free_utf8_string(&path);
        REQUIRE(hash_result == EBPF_SUCCESS);
        REQUIRE(hash_length == hash.size());
        {
            native_epoch epoch;
            REQUIRE(ebpf_native_authorize_module(&id.Guid, hash.data()) == EBPF_SUCCESS);
        }
        characteristics = {
            0,
            sizeof(NPI_CLIENT_CHARACTERISTICS),
            attach,
            detach,
            nullptr,
            {0, sizeof(NPI_REGISTRATION_INSTANCE), &native_npi, &id, 0, nullptr}};
        REQUIRE(NmrRegisterClient(&characteristics, this, &registration.handle) == STATUS_SUCCESS);
        REQUIRE(attached);
        static const wchar_t service[] = L"namespace_native_test";
        size_t maps = 0, programs = 0;
        {
            native_epoch epoch;
            REQUIRE(
                ebpf_native_load(
                    service,
                    static_cast<uint16_t>(sizeof(service) - sizeof(wchar_t)),
                    &id.Guid,
                    &module_handle.value,
                    &maps,
                    &programs) == EBPF_SUCCESS);
        }
        REQUIRE(maps == map_handles.size());
        REQUIRE(programs == program_handles.size());
        map_handles.fill(ebpf_handle_invalid);
        program_handles.fill(ebpf_handle_invalid);
    }

    ~native_module()
    {
        native_epoch epoch;
        CHECK(ebpf_native_test_restore_state(&id.Guid) == EBPF_SUCCESS);
        for (size_t index = 0; index < map_handles.size(); index++) {
            if (map_handles[index] != ebpf_handle_invalid) {
                if (pin_ownership[index] == EBPF_NATIVE_MAP_PIN_CREATED) {
                    auto path = pin_path(index);
                    auto result = ebpf_core_delete_pinning_with_cookie(map_handles[index], &path, pin_cookies[index]);
                    CHECK((result == EBPF_SUCCESS || result == EBPF_KEY_NOT_FOUND));
                }
                CHECK(ebpf_handle_close(map_handles[index]) == EBPF_SUCCESS);
                map_handles[index] = ebpf_handle_invalid;
            }
        }
        for (auto& handle : program_handles) {
            if (handle != ebpf_handle_invalid) {
                CHECK(ebpf_handle_close(handle) == EBPF_SUCCESS);
                handle = ebpf_handle_invalid;
            }
        }
    }

    ebpf_result_t
    load(const GUID& scope)
    {
        native_epoch epoch;
        return ebpf_native_load_programs(
            &scope,
            &id.Guid,
            "BPF:\\",
            map_handles.size(),
            map_handles.data(),
            nullptr,
            program_handles.size(),
            program_handles.data(),
            pin_ownership.data(),
            pin_cookies.data());
    }

    ebpf_native_test_snapshot_t
    snapshot() const
    {
        native_epoch epoch;
        ebpf_native_test_snapshot_t value{};
        REQUIRE(ebpf_native_test_get_snapshot(&id.Guid, &value) == EBPF_SUCCESS);
        return value;
    }

    const GUID&
    module_id() const
    {
        return id.Guid;
    }

    std::array<ebpf_handle_t, 3> map_handles{};
    std::array<ebpf_handle_t, 2> program_handles{};
    std::array<uint8_t, 3> pin_ownership{};
    std::array<uint64_t, 3> pin_cookies{};

  private:
    static NTSTATUS
    attach(HANDLE binding, void* context, const NPI_REGISTRATION_INSTANCE*)
    {
        auto* module = static_cast<native_module*>(context);
        void* provider_context = nullptr;
        const void* dispatch = nullptr;
        auto status = NmrClientAttachProvider(binding, context, &metadata, &provider_context, &dispatch);
        module->attached = NT_SUCCESS(status);
        return status;
    }
    static NTSTATUS
    detach(void*)
    {
        return STATUS_SUCCESS;
    }

    NPI_MODULEID id{sizeof(NPI_MODULEID), MIT_GUID};
    NPI_CLIENT_CHARACTERISTICS characteristics{};
    bool attached = false;
    native_registration registration;
    native_handle module_handle;
};

class native_environment
{
  public:
    native_environment()
    {
        core.initialize();
        REQUIRE(provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    }

  private:
    _ebpf_core_initializer core;
    program_info_provider_t provider;
};

class native_callback_scope
{
  public:
    native_callback_scope(ebpf_native_test_callback_t callback, void* context)
    {
        ebpf_native_test_set_callback(callback, context);
    }
    ~native_callback_scope() { ebpf_native_test_set_callback(nullptr, nullptr); }
};

class native_loading_gate
{
  public:
    static bool
    callback(ebpf_native_test_point_t point, const ebpf_native_test_event_t* event, void* context)
    {
        auto* gate = static_cast<native_loading_gate*>(context);
        if (point != EBPF_NATIVE_TEST_LOADING_UNLOCKED) {
            return false;
        }
        std::unique_lock lock(gate->mutex);
        if (gate->entered) {
            return false;
        }
        gate->captured = *event;
        gate->entered = true;
        gate->condition.notify_all();
        gate->condition.wait(lock, [&]() { return gate->released; });
        return false;
    }
    bool
    wait()
    {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(10), [&]() { return entered || done; }) && entered;
    }
    void
    complete()
    {
        std::lock_guard lock(mutex);
        done = true;
        condition.notify_all();
    }
    void
    release()
    {
        std::lock_guard lock(mutex);
        released = true;
        condition.notify_all();
    }
    ebpf_native_test_event_t captured{};

  private:
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool released = false;
    bool done = false;
};

struct native_gate_release
{
    native_loading_gate& gate;
    ~native_gate_release() { gate.release(); }
};

ebpf_result_t
raw_duplicate_load(const GUID& scope, const GUID& module_id)
{
    native_epoch epoch;
    std::array<ebpf_handle_t, 3> maps;
    std::array<ebpf_handle_t, 2> programs;
    std::array<uint8_t, 3> ownership{};
    maps.fill(ebpf_handle_invalid);
    programs.fill(ebpf_handle_invalid);
    struct output_cleanup
    {
        std::array<ebpf_handle_t, 3>& maps;
        std::array<ebpf_handle_t, 2>& programs;
        std::array<uint8_t, 3>& ownership;
        ~output_cleanup()
        {
            for (size_t index = 0; index < maps.size(); index++) {
                if (maps[index] != ebpf_handle_invalid) {
                    if (ownership[index] == EBPF_NATIVE_MAP_PIN_CREATED) {
                        auto path = pin_path(index);
                        auto result = ebpf_core_delete_pinning_if_matches(maps[index], &path);
                        CHECK((result == EBPF_SUCCESS || result == EBPF_KEY_NOT_FOUND));
                    }
                    CHECK(ebpf_handle_close(maps[index]) == EBPF_SUCCESS);
                }
            }
            for (auto handle : programs) {
                if (handle != ebpf_handle_invalid) {
                    CHECK(ebpf_handle_close(handle) == EBPF_SUCCESS);
                }
            }
        }
    } cleanup{maps, programs, ownership};
    auto result = ebpf_native_load_programs(
        &scope,
        &module_id,
        "BPF:\\",
        maps.size(),
        maps.data(),
        nullptr,
        programs.size(),
        programs.data(),
        ownership.data(),
        nullptr);
    for (auto handle : maps) {
        REQUIRE(handle == ebpf_handle_invalid);
    }
    for (auto handle : programs) {
        REQUIRE(handle == ebpf_handle_invalid);
    }
    return result;
}

void
check_loaded_graph(native_module& module, const GUID& scope)
{
    native_epoch epoch;
    for (size_t index = 0; index < module.map_handles.size(); index++) {
        auto object = reference_object(module.map_handles[index], EBPF_OBJECT_MAP);
        REQUIRE(object->namespace_id == scope);
        auto path = pin_path(index);
        native_handle opened;
        REQUIRE(ebpf_core_get_pinned_object(&scope, &path, &opened.value) == EBPF_SUCCESS);
        auto pinned = reference_object(opened.value, EBPF_OBJECT_MAP);
        REQUIRE(pinned.get() == object.get());
    }
    std::array<ebpf_id_t, 2> program_ids{};
    for (size_t index = 0; index < module.program_handles.size(); index++) {
        auto object = reference_object(module.program_handles[index], EBPF_OBJECT_PROGRAM);
        REQUIRE(object->namespace_id == scope);
        program_ids[index] = object->id;
    }
    auto array = reference_object(module.map_handles[2], EBPF_OBJECT_MAP);
    for (uint32_t key = 0; key < 2; key++) {
        ebpf_id_t id = 0;
        REQUIRE(
            ebpf_map_find_entry(
                reinterpret_cast<ebpf_map_t*>(array.get()),
                sizeof(key),
                reinterpret_cast<uint8_t*>(&key),
                sizeof(id),
                reinterpret_cast<uint8_t*>(&id),
                0) == EBPF_SUCCESS);
        REQUIRE(id == program_ids[key]);
    }
}

class pinned_control
{
  public:
    pinned_control(const GUID& owner, size_t path_index, uint32_t marker, bool insert = true)
        : scope(owner), index(path_index)
    {
        native_epoch epoch;
        cxplat_utf8_string_t name = CXPLAT_UTF8_STRING_FROM_CONST_STRING("native_control");
        ebpf_map_definition_in_memory_t definition{BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};
        REQUIRE(ebpf_core_create_map(&owner, &name, &definition, ebpf_handle_invalid, &handle.value) == EBPF_SUCCESS);
        auto object = reference_object(handle.value, EBPF_OBJECT_MAP);
        id = object->id;
        uint32_t key = 0;
        REQUIRE(
            ebpf_map_update_entry(
                reinterpret_cast<ebpf_map_t*>(object.get()),
                sizeof(key),
                reinterpret_cast<uint8_t*>(&key),
                sizeof(marker),
                reinterpret_cast<uint8_t*>(&marker),
                EBPF_ANY,
                0) == EBPF_SUCCESS);
        if (insert) {
            pin();
        }
    }
    ~pinned_control()
    {
        native_epoch epoch;
        auto path = pin_path(index);
        auto result = ebpf_core_delete_pinning_if_matches(handle.value, &path);
        CHECK((result == EBPF_SUCCESS || result == EBPF_KEY_NOT_FOUND));
    }
    ebpf_result_t
    try_pin()
    {
        auto path = pin_path(index);
        return ebpf_core_update_pinning(&scope, handle.value, &path);
    }
    void
    pin()
    {
        REQUIRE(try_pin() == EBPF_SUCCESS);
    }
    void
    check(uint32_t expected)
    {
        native_epoch epoch;
        auto path = pin_path(index);
        native_handle opened;
        REQUIRE(ebpf_core_get_pinned_object(&scope, &path, &opened.value) == EBPF_SUCCESS);
        auto object = reference_object(opened.value, EBPF_OBJECT_MAP);
        REQUIRE(object->id == id);
        REQUIRE(object->namespace_id == scope);
        uint32_t key = 0, marker = 0;
        REQUIRE(
            ebpf_map_find_entry(
                reinterpret_cast<ebpf_map_t*>(object.get()),
                sizeof(key),
                reinterpret_cast<uint8_t*>(&key),
                sizeof(marker),
                reinterpret_cast<uint8_t*>(&marker),
                0) == EBPF_SUCCESS);
        REQUIRE(marker == expected);
    }
    ebpf_handle_t
    get_handle() const
    {
        return handle.value;
    }
    ebpf_id_t id = EBPF_ID_NONE;

  private:
    GUID scope;
    size_t index;
    native_handle handle;
};

#if defined(CXPLAT_DEBUGGING_FEATURES_ENABLED)
class native_fault_session
{
  public:
    native_fault_session()
    {
        REQUIRE(cxplat_fault_injection_initialize(0) == CXPLAT_STATUS_SUCCESS);
        cxplat_fault_injection_suspend();
        auto result = cxplat_fault_injection_add_module(GetModuleHandle(nullptr));
        if (result != CXPLAT_STATUS_SUCCESS) {
            cxplat_fault_injection_resume();
            cxplat_fault_injection_uninitialize();
        }
        REQUIRE(result == CXPLAT_STATUS_SUCCESS);
    }
    ~native_fault_session()
    {
        cxplat_fault_injection_resume();
        cxplat_fault_injection_uninitialize();
    }
};

struct native_fault_target
{
    ebpf_native_test_point_t point;
    size_t ordinal;
    pinned_control* replacement = nullptr;
    size_t observed = 0;
    size_t faults = 0;
    bool active = false;
    bool replaced = false;
    bool replacement_failed = false;
    DWORD thread = GetCurrentThreadId();

    static bool
    callback(ebpf_native_test_point_t operation, const ebpf_native_test_event_t* event, void* context)
    {
        auto* target = static_cast<native_fault_target*>(context);
        if (GetCurrentThreadId() != target->thread || !target->active || operation != target->point ||
            ++target->observed != target->ordinal) {
            return false;
        }
        cxplat_fault_injection_resume();
        bool fail = cxplat_fault_injection_inject_fault();
        cxplat_fault_injection_suspend();
        if (!fail) {
            return false;
        }
        target->faults++;
        if (target->replacement != nullptr) {
            auto path = pin_path(1);
            target->replacement_failed =
                event->name == nullptr || strcmp(event->name, "ns_created") != 0 ||
                ebpf_core_update_pinning(&event->namespace_id, ebpf_handle_invalid, &path) != EBPF_SUCCESS ||
                target->replacement->try_pin() != EBPF_SUCCESS;
            target->replaced = !target->replacement_failed;
        }
        return true;
    }
};
#endif
} // namespace

TEST_CASE("namespace_NU40_native_loading_latch_and_completed_missing_controls", "[namespace][native_runtime]")
{
    native_environment environment;
    native_module module;
    auto initialized = module.snapshot();
    REQUIRE(initialized.state == EBPF_NATIVE_TEST_INITIALIZED);
    ebpf_request_context_t request{};
    request.namespace_id = namespace_a;
    native_loading_gate gate;
    native_callback_scope callback(native_loading_gate::callback, &gate);
    ebpf_result_t first = EBPF_INVALID_STATE;
    std::jthread loader([&]() {
        first = module.load(request.namespace_id);
        gate.complete();
    });
    native_gate_release unblock{gate};
    REQUIRE(gate.wait());
    REQUIRE(gate.captured.module_id == module.module_id());
    REQUIRE(gate.captured.namespace_id == namespace_a);
    auto loading = module.snapshot();
    REQUIRE(loading.state == EBPF_NATIVE_TEST_LOADING);
    REQUIRE(loading.references == initialized.references + 1);
    REQUIRE(raw_duplicate_load(namespace_b, module.module_id()) == EBPF_OBJECT_ALREADY_EXISTS);
    auto unchanged = module.snapshot();
    REQUIRE(unchanged.state == EBPF_NATIVE_TEST_LOADING);
    REQUIRE(unchanged.references == loading.references);
    gate.release();
    loader.join();
    REQUIRE(first == EBPF_SUCCESS);
    check_loaded_graph(module, namespace_a);
    auto loaded = module.snapshot();
    REQUIRE(loaded.state == EBPF_NATIVE_TEST_LOADED);
    const int64_t expected_references = initialized.references + static_cast<int64_t>(module.program_handles.size());
    REQUIRE(loaded.references == expected_references);
    REQUIRE(raw_duplicate_load(namespace_b, module.module_id()) == EBPF_OBJECT_ALREADY_EXISTS);
    REQUIRE(module.snapshot().references == loaded.references);
    GUID missing{};
    REQUIRE(ebpf_guid_create(&missing) == EBPF_SUCCESS);
    REQUIRE(raw_duplicate_load(namespace_b, missing) == EBPF_OBJECT_NOT_FOUND);
    {
        native_epoch epoch;
        for (size_t index = 0; index < pin_paths.size(); index++) {
            auto path = pin_path(index);
            ebpf_handle_t hidden = ebpf_handle_invalid;
            REQUIRE(ebpf_core_get_pinned_object(&namespace_b, &path, &hidden) == EBPF_KEY_NOT_FOUND);
            REQUIRE(hidden == ebpf_handle_invalid);
        }
    }
}

TEST_CASE("namespace_NU40_native_transient_unloading_detaching_restore_before_cleanup", "[namespace][native_runtime]")
{
    native_environment environment;
    native_module module;
    auto initial = module.snapshot();
    for (auto transient : {EBPF_NATIVE_TEST_TRANSIENT_UNLOADING, EBPF_NATIVE_TEST_TRANSIENT_DETACHING}) {
        {
            native_epoch epoch;
            REQUIRE(ebpf_native_test_override_state(&module.module_id(), transient) == EBPF_SUCCESS);
        }
        auto overridden = module.snapshot();
        REQUIRE(overridden.transient_override);
        REQUIRE(
            (transient == EBPF_NATIVE_TEST_TRANSIENT_UNLOADING ? overridden.state == EBPF_NATIVE_TEST_UNLOADING
                                                               : overridden.detaching));
        REQUIRE(raw_duplicate_load(namespace_b, module.module_id()) == EBPF_EXTENSION_FAILED_TO_LOAD);
        auto restored = module.snapshot();
        REQUIRE(restored.state == initial.state);
        REQUIRE_FALSE(restored.detaching);
        REQUIRE_FALSE(restored.transient_override);
        REQUIRE(restored.references == initial.references);
    }
    REQUIRE(module.load(namespace_a) == EBPF_SUCCESS);
    check_loaded_graph(module, namespace_a);
}

#if defined(CXPLAT_DEBUGGING_FEATURES_ENABLED)
TEST_CASE("namespace_native_internal_failure_rollback_and_fresh_module_retry", "[namespace][native_runtime]")
{
    if (cxplat_fault_injection_is_enabled()) {
        WARN("An external fault campaign owns its log; do not reset that campaign.");
        return;
    }
    native_fault_session faults;
    native_environment environment;
    pinned_control reused(namespace_a, 0, 0x1111);
    pinned_control foreign(namespace_b, 1, 0x2222);
    pinned_control replacement(namespace_a, 1, 0x3333, false);
    struct failure_case
    {
        ebpf_native_test_point_t point;
        size_t ordinal;
        bool replace;
    };
    const failure_case cases[] = {
        {EBPF_NATIVE_TEST_MAP_ALLOCATION, 1, false},
        {EBPF_NATIVE_TEST_MAP_PINNED, 1, false},
        {EBPF_NATIVE_TEST_PROGRAM_ALLOCATION, 1, false},
        {EBPF_NATIVE_TEST_PROGRAM_CREATED, 1, false},
        {EBPF_NATIVE_TEST_INITIAL_VALUE, 1, false},
        {EBPF_NATIVE_TEST_INITIAL_VALUE, 2, false},
        {EBPF_NATIVE_TEST_MAP_PINNED, 1, true},
    };
    for (const auto& test : cases) {
        CAPTURE(test.point, test.ordinal, test.replace);
        cxplat_fault_injection_reset();
        native_fault_target target{test.point, test.ordinal, test.replace ? &replacement : nullptr};
        native_callback_scope callback(native_fault_target::callback, &target);
        for (size_t attempt = 0; attempt < 2; attempt++) {
            target.observed = 0;
            {
                native_module module;
                target.active = true;
                auto result = module.load(namespace_a);
                target.active = false;
                if (attempt == 0) {
                    REQUIRE(result == EBPF_NO_MEMORY);
                    REQUIRE(target.faults == 1);
                    REQUIRE_FALSE(target.replacement_failed);
                    REQUIRE(target.replaced == test.replace);
                    reused.check(0x1111);
                    foreign.check(0x2222);
                    if (test.replace) {
                        replacement.check(0x3333);
                    }
                    {
                        native_epoch epoch;
                        for (size_t index = 1; index < pin_paths.size(); index++) {
                            auto path = pin_path(index);
                            native_handle opened;
                            auto found = ebpf_core_get_pinned_object(&namespace_a, &path, &opened.value);
                            REQUIRE(found == (test.replace && index == 1 ? EBPF_SUCCESS : EBPF_KEY_NOT_FOUND));
                        }
                        ebpf_id_t id = EBPF_ID_NONE;
                        REQUIRE(
                            ebpf_object_get_next_id(&namespace_a, 0, EBPF_OBJECT_PROGRAM, &id) == EBPF_NO_MORE_KEYS);
                    }
                    REQUIRE(raw_duplicate_load(namespace_b, module.module_id()) == EBPF_OBJECT_ALREADY_EXISTS);
                } else {
                    REQUIRE(result == EBPF_SUCCESS);
                    REQUIRE(target.faults == 1);
                    REQUIRE(module.pin_ownership[0] == EBPF_NATIVE_MAP_PIN_REUSED);
                    REQUIRE(
                        module.pin_ownership[1] ==
                        (test.replace ? EBPF_NATIVE_MAP_PIN_REUSED : EBPF_NATIVE_MAP_PIN_CREATED));
                    check_loaded_graph(module, namespace_a);
                    reused.check(0x1111);
                    foreign.check(0x2222);
                }
            }
            ebpf_epoch_synchronize();
            reused.check(0x1111);
            foreign.check(0x2222);
        }
        if (test.replace) {
            native_epoch epoch;
            auto path = pin_path(1);
            REQUIRE(ebpf_core_delete_pinning_if_matches(replacement.get_handle(), &path) == EBPF_SUCCESS);
        }
        native_epoch epoch;
        auto object = reference_object(reused.get_handle(), EBPF_OBJECT_MAP);
        REQUIRE(object->base.reference_count == 3);
        REQUIRE(object->base.user_reference_count == 2);
        REQUIRE(object->pinned_path_count == 1);
        auto foreign_object = reference_object(foreign.get_handle(), EBPF_OBJECT_MAP);
        REQUIRE(foreign_object->base.reference_count == 3);
        REQUIRE(foreign_object->base.user_reference_count == 2);
        REQUIRE(foreign_object->pinned_path_count == 1);
        auto replacement_object = reference_object(replacement.get_handle(), EBPF_OBJECT_MAP);
        REQUIRE(replacement_object->base.reference_count == 2);
        REQUIRE(replacement_object->base.user_reference_count == 1);
        REQUIRE(replacement_object->pinned_path_count == 0);
    }
}
#endif
