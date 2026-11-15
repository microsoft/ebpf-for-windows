// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS

#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "ebpf_async.h"
#include "ebpf_epoch.h"
#include "ebpf_handle.h"
#include "ebpf_link.h"
#include "ebpf_maps.h"
#include "ebpf_namespace.h"
#include "ebpf_object.h"
#include "ebpf_object_test.h"
#include "ebpf_pinning_table.h"
#include "ebpf_program.h"
#include "execution_context_unit_test_jit.h"
#include "helpers.h"
#include "hook_helper.h"
#include "test_helper.hpp"

#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <semaphore>
#include <set>
#include <thread>

namespace {
const GUID namespace_default{};
const GUID namespace_a = {0x00112233, 0x4455, 0x6677, {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}};
const GUID namespace_b = {0x00112233, 0x4455, 0x6677, {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}};
const std::array<GUID, 3> namespaces = {namespace_default, namespace_a, namespace_b};
const std::array<ebpf_object_type_t, 3> object_types = {EBPF_OBJECT_MAP, EBPF_OBJECT_PROGRAM, EBPF_OBJECT_LINK};

class namespace_epoch
{
  public:
    namespace_epoch() { ebpf_epoch_enter(&_state); }
    ~namespace_epoch() { ebpf_epoch_exit(&_state); }

  private:
    ebpf_epoch_state_t _state{};
};

struct namespace_test_object
{
    ebpf_core_object_t object;
    std::atomic<size_t>* freed;
    std::atomic<size_t>* user_refs_zeroed;
    std::binary_semaphore* free_signal;
};

using object_ptr = std::unique_ptr<ebpf_core_object_t, ebpf_object_deleter<ebpf_core_object_t>>;
using pin_table_ptr = std::unique_ptr<ebpf_pinning_table_t, decltype(&ebpf_pinning_table_free)>;

ebpf_result_t
try_make_object(
    const GUID& namespace_id,
    ebpf_object_type_t type,
    std::atomic<size_t>& freed,
    object_ptr& result_object,
    std::atomic<size_t>* user_refs_zeroed = nullptr,
    std::binary_semaphore* free_signal = nullptr)
{
    auto* object =
        static_cast<namespace_test_object*>(ebpf_allocate_with_tag(sizeof(namespace_test_object), EBPF_TEST_POOL_TAG));
    if (object == nullptr) {
        return EBPF_NO_MEMORY;
    }
    memset(object, 0, sizeof(*object));
    object->freed = &freed;
    object->user_refs_zeroed = user_refs_zeroed;
    object->free_signal = free_signal;
    auto result = EBPF_OBJECT_INITIALIZE(
        &namespace_id,
        &object->object,
        type,
        [](ebpf_core_object_t* core_object) {
            auto* test_object = reinterpret_cast<namespace_test_object*>(core_object);
            auto* freed_counter = test_object->freed;
            auto* notification = test_object->free_signal;
            ebpf_free(test_object);
            freed_counter->fetch_add(1);
            if (notification != nullptr) {
                notification->release();
            }
        },
        nullptr,
        [](ebpf_core_object_t* core_object) {
            auto* test_object = reinterpret_cast<namespace_test_object*>(core_object);
            if (test_object->user_refs_zeroed != nullptr) {
                test_object->user_refs_zeroed->fetch_add(1);
            }
        },
        nullptr);
    if (result != EBPF_SUCCESS) {
        ebpf_free(object);
    } else {
        result_object.reset(&object->object);
    }
    return result;
}

object_ptr
make_object(
    const GUID& namespace_id,
    ebpf_object_type_t type,
    std::atomic<size_t>& freed,
    std::atomic<size_t>* user_refs_zeroed = nullptr,
    std::binary_semaphore* free_signal = nullptr)
{
    object_ptr object;
    auto result = try_make_object(namespace_id, type, freed, object, user_refs_zeroed, free_signal);
    REQUIRE(result == EBPF_SUCCESS);
    return object;
}

pin_table_ptr
make_pin_table()
{
    ebpf_pinning_table_t* table = nullptr;
    REQUIRE(ebpf_pinning_table_allocate(&table) == EBPF_SUCCESS);
    return pin_table_ptr(table, ebpf_pinning_table_free);
}

cxplat_utf8_string_t
path_string(std::string& path)
{
    return {reinterpret_cast<uint8_t*>(path.data()), path.size()};
}

map_ptr
make_map(
    const GUID& namespace_id,
    ebpf_map_type_t type = BPF_MAP_TYPE_ARRAY,
    ebpf_handle_t inner_handle = ebpf_handle_invalid)
{
    cxplat_utf8_string_t name{};
    ebpf_map_definition_in_memory_t definition{type, sizeof(uint32_t), sizeof(uint32_t), 4};
    ebpf_map_t* map = nullptr;
    REQUIRE(ebpf_map_create(&namespace_id, &name, &definition, inner_handle, &map) == EBPF_SUCCESS);
    return map_ptr(map);
}

program_ptr
make_program(const GUID& namespace_id)
{
    ebpf_program_parameters_t parameters{EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE};
    ebpf_program_t* program = nullptr;
    REQUIRE(ebpf_program_create(&namespace_id, &parameters, &program) == EBPF_SUCCESS);
    return program_ptr(program);
}

link_ptr
make_link(const GUID& namespace_id)
{
    ebpf_link_t* link = nullptr;
    REQUIRE(ebpf_link_create(&namespace_id, EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &link) == EBPF_SUCCESS);
    return link_ptr(link);
}

class namespace_handle
{
  public:
    explicit namespace_handle(ebpf_core_object_t* object)
    {
        REQUIRE(ebpf_handle_create(&_handle, &object->base) == EBPF_SUCCESS);
    }
    ~namespace_handle() { ebpf_assert_success(ebpf_handle_close(_handle)); }
    ebpf_handle_t
    get() const
    {
        return _handle;
    }

  private:
    ebpf_handle_t _handle = ebpf_handle_invalid;
};

class namespace_callback_scope
{
  public:
    namespace_callback_scope(ebpf_object_test_callback_t callback, void* context)
    {
        ebpf_object_test_set_callback(callback, context);
    }
    ~namespace_callback_scope() { ebpf_object_test_set_callback(nullptr, nullptr); }
};

class namespace_operation_gate
{
  public:
    namespace_operation_gate(ebpf_object_test_point_t operation, ebpf_id_t id = 0) : point(operation), target(id) {}

    static bool
    callback(ebpf_object_test_point_t operation, const ebpf_core_object_t* object, void* context)
    {
        auto* gate = static_cast<namespace_operation_gate*>(context);
        if (operation != gate->point || (object == nullptr && operation != EBPF_OBJECT_TEST_BEFORE_ASYNC_CANCEL) ||
            (gate->target != 0 && (object == nullptr || object->id != gate->target))) {
            return false;
        }
        std::unique_lock lock(gate->mutex);
        if (gate->reached) {
            return false;
        }
        gate->observed = object;
        gate->reached = true;
        gate->condition.notify_all();
        gate->condition.wait(lock, [&]() { return gate->released; });
        return false;
    }

    bool
    wait()
    {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(10), [&]() { return reached || completed; }) && reached;
    }

    void
    complete()
    {
        std::lock_guard lock(mutex);
        completed = true;
        condition.notify_all();
    }

    void
    release()
    {
        std::lock_guard lock(mutex);
        released = true;
        condition.notify_all();
    }

    const ebpf_core_object_t* observed = nullptr;

  private:
    const ebpf_object_test_point_t point;
    const ebpf_id_t target;
    std::mutex mutex;
    std::condition_variable condition;
    bool reached = false;
    bool completed = false;
    bool released = false;
};

class namespace_gate_release
{
  public:
    explicit namespace_gate_release(namespace_operation_gate& operation_gate) : gate(operation_gate) {}
    ~namespace_gate_release() { gate.release(); }

  private:
    namespace_operation_gate& gate;
};

#if defined(CXPLAT_DEBUGGING_FEATURES_ENABLED)
class namespace_fault_session
{
  public:
    namespace_fault_session()
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

    ~namespace_fault_session()
    {
        cxplat_fault_injection_resume();
        cxplat_fault_injection_uninitialize();
    }
};

struct namespace_fault_target
{
    ebpf_object_test_point_t point;
    size_t ordinal = 1;
    size_t observed = 0;
    size_t faults = 0;
    bool active = false;
    DWORD thread = GetCurrentThreadId();

    static bool
    callback(ebpf_object_test_point_t operation, const ebpf_core_object_t*, void* context)
    {
        auto* target = static_cast<namespace_fault_target*>(context);
        if (GetCurrentThreadId() != target->thread || operation != target->point || !target->active ||
            ++target->observed != target->ordinal) {
            return false;
        }
        cxplat_fault_injection_resume();
        bool fail = cxplat_fault_injection_inject_fault();
        cxplat_fault_injection_suspend();
        target->faults += fail ? 1 : 0;
        return fail;
    }
};
#endif
} // namespace

TEST_CASE("namespace object ID and traversal matrix", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        std::vector<object_ptr> objects;
        for (const auto& type : object_types) {
            for (const auto& namespace_id : namespaces) {
                objects.push_back(make_object(namespace_id, type, freed));
            }
        }
        std::set<ebpf_id_t> global_ids;
        for (const auto& object : objects) {
            REQUIRE(global_ids.insert(object->id).second);
            for (const auto& namespace_id : namespaces) {
                for (const auto& type : object_types) {
                    ebpf_core_object_t* found = reinterpret_cast<ebpf_core_object_t*>(1);
                    bool matches =
                        type == object->type && memcmp(&object->namespace_id, &namespace_id, sizeof(GUID)) == 0;
                    REQUIRE(
                        EBPF_OBJECT_REFERENCE_BY_ID(&namespace_id, object->id, type, &found) ==
                        (matches ? EBPF_SUCCESS : EBPF_KEY_NOT_FOUND));
                    REQUIRE(found == (matches ? object.get() : nullptr));
                    EBPF_OBJECT_RELEASE_REFERENCE(found);
                }
            }
            REQUIRE(object->base.reference_count == 1);
        }
        for (const auto& namespace_id : namespaces) {
            for (const auto& type : object_types) {
                std::set<ebpf_id_t> expected;
                for (const auto& object : objects) {
                    if (object->type == type && memcmp(&object->namespace_id, &namespace_id, sizeof(GUID)) == 0) {
                        expected.insert(object->id);
                    }
                }
                std::set<ebpf_id_t> ids;
                ebpf_id_t cursor = 0;
                ebpf_id_t next;
                while (ebpf_object_get_next_id(&namespace_id, cursor, type, &next) == EBPF_SUCCESS) {
                    REQUIRE(next > cursor);
                    REQUIRE(ids.insert(next).second);
                    cursor = next;
                }
                REQUIRE(ids == expected);
                REQUIRE(
                    ebpf_object_get_next_id(&namespace_id, (std::numeric_limits<ebpf_id_t>::max)(), type, &next) ==
                    EBPF_NO_MORE_KEYS);
                for (const auto& object : objects) {
                    auto expected_next = expected.upper_bound(object->id);
                    auto result = ebpf_object_get_next_id(&namespace_id, object->id, type, &next);
                    REQUIRE(result == (expected_next == expected.end() ? EBPF_NO_MORE_KEYS : EBPF_SUCCESS));
                    if (result == EBPF_SUCCESS) {
                        REQUIRE(next == *expected_next);
                    }
                }
                ids.clear();
                ebpf_core_object_t* previous = nullptr;
                for (;;) {
                    ebpf_core_object_t* found = nullptr;
                    EBPF_OBJECT_REFERENCE_NEXT_OBJECT(&namespace_id, previous, type, &found);
                    EBPF_OBJECT_RELEASE_REFERENCE(previous);
                    previous = found;
                    if (found == nullptr) {
                        break;
                    }
                    REQUIRE(ids.insert(found->id).second);
                }
                REQUIRE(ids == expected);
                ebpf_core_object_t* absent = reinterpret_cast<ebpf_core_object_t*>(1);
                REQUIRE(
                    EBPF_OBJECT_REFERENCE_BY_ID(
                        &namespace_id, (std::numeric_limits<ebpf_id_t>::max)(), type, &absent) == EBPF_KEY_NOT_FOUND);
                REQUIRE(absent == nullptr);
            }
        }
        for (const auto& type : object_types) {
            std::set<ebpf_id_t> ids;
            ebpf_core_object_t* previous = nullptr;
            for (;;) {
                ebpf_core_object_t* found = nullptr;
                EBPF_OBJECT_REFERENCE_NEXT_OBJECT_FOR_TEARDOWN(previous, type, &found);
                EBPF_OBJECT_RELEASE_REFERENCE(previous);
                previous = found;
                if (found == nullptr) {
                    break;
                }
                REQUIRE(ids.insert(found->id).second);
            }
            REQUIRE(ids.size() == namespaces.size());
        }
        for (const auto& previous : objects) {
            ebpf_core_object_t* found = nullptr;
            EBPF_OBJECT_REFERENCE_NEXT_OBJECT(&namespace_a, previous.get(), EBPF_OBJECT_MAP, &found);
            if (found != nullptr) {
                REQUIRE(found->namespace_id == namespace_a);
                REQUIRE(found->type == EBPF_OBJECT_MAP);
                EBPF_OBJECT_RELEASE_REFERENCE(found);
            }
        }
    }
    REQUIRE(freed == 9);
}

TEST_CASE("namespace deleted ID cursors and epoch references", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        {
            namespace_epoch epoch;
            auto first = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
            auto hidden = make_object(namespace_b, EBPF_OBJECT_MAP, freed);
            auto last = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
            auto deleted_id = first->id;
            auto last_id = last->id;
            ebpf_core_object_t* referenced = nullptr;
            REQUIRE(EBPF_OBJECT_REFERENCE_BY_ID(&namespace_a, last_id, EBPF_OBJECT_MAP, &referenced) == EBPF_SUCCESS);
            first.reset();
            ebpf_id_t next;
            REQUIRE(ebpf_object_get_next_id(&namespace_a, deleted_id, EBPF_OBJECT_MAP, &next) == EBPF_SUCCESS);
            REQUIRE(next == last_id);
            REQUIRE(ebpf_object_get_next_id(&namespace_a, deleted_id - 1, EBPF_OBJECT_MAP, &next) == EBPF_SUCCESS);
            REQUIRE(next == last_id);
            ebpf_core_object_t* found = nullptr;
            REQUIRE(
                EBPF_OBJECT_REFERENCE_BY_ID(&namespace_a, deleted_id, EBPF_OBJECT_MAP, &found) == EBPF_KEY_NOT_FOUND);
            last.reset();
            REQUIRE(referenced->id == last_id);
            REQUIRE(memcmp(&referenced->namespace_id, &namespace_a, sizeof(GUID)) == 0);
            EBPF_OBJECT_RELEASE_REFERENCE(referenced);
            REQUIRE(ebpf_object_get_next_id(&namespace_a, deleted_id, EBPF_OBJECT_MAP, &next) == EBPF_NO_MORE_KEYS);
        }
        ebpf_epoch_synchronize();
    }
    REQUIRE(freed == 3);
}

TEST_CASE("namespace composite pins and conditional rollback", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    std::atomic<size_t> user_refs_zeroed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto table = make_pin_table();
        std::vector<object_ptr> objects;
        cxplat_utf8_string_t path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("shared/path");
        for (const auto& namespace_id : namespaces) {
            objects.push_back(make_object(namespace_id, EBPF_OBJECT_MAP, freed));
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_id, &path, objects.back().get()) == EBPF_SUCCESS);
            REQUIRE(objects.back()->pinned_path_count == 1);
            REQUIRE(objects.back()->base.user_reference_count == 1);
        }
        for (size_t i = 0; i < namespaces.size(); i++) {
            ebpf_core_object_t* found = nullptr;
            REQUIRE(ebpf_pinning_table_find(table.get(), &namespaces[i], &path, &found) == EBPF_SUCCESS);
            REQUIRE(found == objects[i].get());
            EBPF_OBJECT_RELEASE_REFERENCE(found);
            REQUIRE(
                ebpf_pinning_table_insert(table.get(), &namespaces[i], &path, objects[i].get()) ==
                EBPF_OBJECT_ALREADY_EXISTS);
            REQUIRE(objects[i]->base.reference_count == 2);
        }
        auto replacement = make_object(namespace_a, EBPF_OBJECT_MAP, freed, &user_refs_zeroed);
        REQUIRE(
            ebpf_pinning_table_insert(table.get(), &namespace_a, &path, replacement.get()) ==
            EBPF_OBJECT_ALREADY_EXISTS);
        REQUIRE(replacement->base.reference_count == 1);
        REQUIRE(user_refs_zeroed == 0);
        REQUIRE(
            ebpf_pinning_table_insert(table.get(), &namespace_b, &path, replacement.get()) == EBPF_INVALID_ARGUMENT);
        REQUIRE(replacement->pinned_path_count == 0);
        REQUIRE(
            ebpf_pinning_table_delete_if_matches(table.get(), &namespace_b, &path, objects[1].get()) ==
            EBPF_KEY_NOT_FOUND);
        REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &path) == EBPF_SUCCESS);
        REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &path, replacement.get()) == EBPF_SUCCESS);
        REQUIRE(
            ebpf_pinning_table_delete_if_matches(table.get(), &namespace_a, &path, objects[1].get()) ==
            EBPF_KEY_NOT_FOUND);
        ebpf_core_object_t* found = nullptr;
        REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_a, &path, &found) == EBPF_SUCCESS);
        REQUIRE(found == replacement.get());
        EBPF_OBJECT_RELEASE_REFERENCE(found);
        REQUIRE(
            ebpf_pinning_table_delete_if_matches(table.get(), &namespace_a, &path, replacement.get()) == EBPF_SUCCESS);
        REQUIRE(user_refs_zeroed == 1);
        REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &path) == EBPF_KEY_NOT_FOUND);
        REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_a, &path, &found) == EBPF_KEY_NOT_FOUND);
        REQUIRE(found == nullptr);
        REQUIRE(objects[0]->pinned_path_count == 1);
        REQUIRE(objects[2]->pinned_path_count == 1);
        table.reset();
        for (const auto& object : objects) {
            REQUIRE(object->pinned_path_count == 0);
            REQUIRE(object->base.user_reference_count == 0);
            REQUIRE(object->base.reference_count == 1);
        }
    }
    REQUIRE(freed == 4);
}

TEST_CASE(
    "namespace insertion cookie exhaustion does not publish or reuse an insertion", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto table = make_pin_table();
        auto object = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
        cxplat_utf8_string_t path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("cookie/exhaustion");
        ebpf_pinning_table_test_set_cookie_counter(table.get(), UINT64_MAX - 1);
        uint64_t cookie = 0;
        REQUIRE(
            ebpf_pinning_table_insert_with_cookie(table.get(), &namespace_a, &path, object.get(), &cookie) ==
            EBPF_SUCCESS);
        REQUIRE(cookie == UINT64_MAX);
        REQUIRE(
            ebpf_pinning_table_delete_with_cookie(table.get(), &namespace_a, &path, object.get(), cookie) ==
            EBPF_SUCCESS);
        uint64_t unchanged = 42;
        REQUIRE(
            ebpf_pinning_table_insert_with_cookie(table.get(), &namespace_a, &path, object.get(), &unchanged) ==
            EBPF_ARITHMETIC_OVERFLOW);
        REQUIRE(unchanged == 42);
        ebpf_core_object_t* found = nullptr;
        REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_a, &path, &found) == EBPF_KEY_NOT_FOUND);
        REQUIRE(object->pinned_path_count == 0);
    }
    REQUIRE(freed == 1);
}

TEST_CASE("namespace pending query completion races a borrowed cancellation context", "[namespace][namespace_objects]")
{
    _ebpf_core_initializer core;
    core.initialize();
    namespace_epoch epoch;
    ebpf_map_definition_in_memory_t definition{BPF_MAP_TYPE_RINGBUF, 0, 0, 65536};
    cxplat_utf8_string_t name = CXPLAT_UTF8_STRING_FROM_CONST_STRING("cancel_race");
    ebpf_map_t* raw_map = nullptr;
    REQUIRE(ebpf_map_create(&namespace_a, &name, &definition, ebpf_handle_invalid, &raw_map) == EBPF_SUCCESS);
    std::unique_ptr<ebpf_map_t, ebpf_object_deleter<ebpf_map_t>> map(raw_map);
    struct completion_state
    {
        std::atomic<size_t> count{0};
        ebpf_result_t result = EBPF_PENDING;
    } completion;
    ebpf_operation_map_async_query_reply_t reply{};
    uint8_t* buffer = nullptr;
    size_t consumer = 0;
    REQUIRE(ebpf_map_query_buffer(map.get(), 0, &buffer, &consumer) == EBPF_SUCCESS);
    reply.async_query_result.consumer = consumer;
    REQUIRE(ebpf_async_set_completion_callback(&completion, [](void* context, size_t, ebpf_result_t result) {
                auto* state = static_cast<completion_state*>(context);
                state->result = result;
                state->count.fetch_add(1);
            }) == EBPF_SUCCESS);
    auto query_result = ebpf_map_async_query(map.get(), 0, &reply.async_query_result, &completion);
    if (query_result != EBPF_PENDING) {
        CHECK(ebpf_async_reset_completion_callback(&completion) == EBPF_SUCCESS);
    }
    REQUIRE(query_result == EBPF_PENDING);
    namespace_operation_gate gate(EBPF_OBJECT_TEST_BEFORE_ASYNC_CANCEL);
    namespace_callback_scope callback(namespace_operation_gate::callback, &gate);
    bool canceled = false;
    std::jthread canceler([&] {
        canceled = ebpf_core_cancel_protocol_handler(&completion);
        gate.complete();
    });
    namespace_gate_release unblock(gate);
    REQUIRE(gate.wait());
    uint64_t value = 42;
    REQUIRE(ebpf_ring_buffer_map_output(map.get(), reinterpret_cast<uint8_t*>(&value), sizeof(value)) == EBPF_SUCCESS);
    gate.release();
    canceler.join();
    REQUIRE(canceled);
    REQUIRE(completion.count == 1);
    REQUIRE(completion.result == EBPF_SUCCESS);
}

TEST_CASE("namespace pin identity uses every GUID byte", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto table = make_pin_table();
        cxplat_utf8_string_t path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("same");
        std::vector<object_ptr> objects;
        for (size_t i = 0; i < sizeof(GUID); i++) {
            GUID namespace_id{};
            reinterpret_cast<uint8_t*>(&namespace_id)[i] = 1;
            objects.push_back(make_object(namespace_id, EBPF_OBJECT_MAP, freed));
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_id, &path, objects.back().get()) == EBPF_SUCCESS);
        }
        for (const auto& object : objects) {
            ebpf_core_object_t* found = nullptr;
            REQUIRE(ebpf_pinning_table_find(table.get(), &object->namespace_id, &path, &found) == EBPF_SUCCESS);
            REQUIRE(found == object.get());
            EBPF_OBJECT_RELEASE_REFERENCE(found);
        }
        ebpf_core_object_t* found = nullptr;
        REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_default, &path, &found) == EBPF_KEY_NOT_FOUND);
    }
    REQUIRE(freed == sizeof(GUID));
}

TEST_CASE("namespace pin snapshots and lexical cursors", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto table = make_pin_table();
        auto visible = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
        auto hidden = make_object(namespace_b, EBPF_OBJECT_MAP, freed);
        auto program = make_object(namespace_a, EBPF_OBJECT_PROGRAM, freed);
        std::vector<std::string> names = {"a", "aa", "ab", "b", "ba"};
        for (auto& name : names) {
            auto path = path_string(name);
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_b, &path, hidden.get()) == EBPF_SUCCESS);
            if (name != "ab") {
                REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &path, visible.get()) == EBPF_SUCCESS);
            }
        }
        cxplat_utf8_string_t program_path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("az");
        REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &program_path, program.get()) == EBPF_SUCCESS);
        uint16_t count = 99;
        ebpf_pinning_entry_t* entries = reinterpret_cast<ebpf_pinning_entry_t*>(1);
        REQUIRE(
            ebpf_pinning_table_enumerate_entries(table.get(), &namespace_default, EBPF_OBJECT_MAP, &count, &entries) ==
            EBPF_SUCCESS);
        REQUIRE(count == 0);
        REQUIRE(entries == nullptr);
        REQUIRE(
            ebpf_pinning_table_enumerate_entries(table.get(), &namespace_a, EBPF_OBJECT_MAP, &count, &entries) ==
            EBPF_SUCCESS);
        REQUIRE(count == 4);
        REQUIRE(visible->base.reference_count == 9);
        for (uint16_t i = 0; i < count; i++) {
            REQUIRE(entries[i].object == visible.get());
            REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &entries[i].path) == EBPF_SUCCESS);
        }
        REQUIRE(visible->pinned_path_count == 0);
        REQUIRE(visible->base.reference_count == 5);
        for (uint16_t i = 0; i < count; i++) {
            REQUIRE(entries[i].path.length != 0);
            REQUIRE(entries[i].object->namespace_id == namespace_a);
        }
        ebpf_pinning_entries_release(count, entries);
        REQUIRE(visible->base.reference_count == 1);
        for (auto& name : names) {
            auto path = path_string(name);
            if (name != "ab") {
                REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &path, visible.get()) == EBPF_SUCCESS);
            }
        }
        std::vector<std::pair<std::string, std::string>> cursors = {
            {"", "a"}, {"a", "aa"}, {"aaa", "az"}, {"ab", "az"}, {"az", "b"}, {"b", "ba"}};
        for (auto& [cursor, expected] : cursors) {
            auto start = path_string(cursor);
            std::array<uint8_t, 32> buffer{};
            cxplat_utf8_string_t next{buffer.data(), buffer.size()};
            auto type = EBPF_OBJECT_UNKNOWN;
            REQUIRE(ebpf_pinning_table_get_next_path(table.get(), &namespace_a, &type, &start, &next) == EBPF_SUCCESS);
            REQUIRE(std::string(reinterpret_cast<char*>(next.value), next.length) == expected);
            REQUIRE(type == (expected == "az" ? EBPF_OBJECT_PROGRAM : EBPF_OBJECT_MAP));
        }
        cxplat_utf8_string_t deleted = CXPLAT_UTF8_STRING_FROM_CONST_STRING("aa");
        REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &deleted) == EBPF_SUCCESS);
        std::array<uint8_t, 32> buffer{};
        cxplat_utf8_string_t next{buffer.data(), buffer.size()};
        auto type = EBPF_OBJECT_MAP;
        REQUIRE(ebpf_pinning_table_get_next_path(table.get(), &namespace_a, &type, &deleted, &next) == EBPF_SUCCESS);
        REQUIRE(std::string(reinterpret_cast<char*>(next.value), next.length) == "b");
        next.length = 0;
        REQUIRE(
            ebpf_pinning_table_get_next_path(table.get(), &namespace_a, &type, &deleted, &next) ==
            EBPF_INSUFFICIENT_BUFFER);
        cxplat_utf8_string_t end = CXPLAT_UTF8_STRING_FROM_CONST_STRING("zz");
        next.length = buffer.size();
        REQUIRE(ebpf_pinning_table_get_next_path(table.get(), &namespace_a, &type, &end, &next) == EBPF_NO_MORE_KEYS);
        REQUIRE(
            ebpf_pinning_table_get_next_path(table.get(), &namespace_default, &type, &deleted, &next) ==
            EBPF_NO_MORE_KEYS);
    }
    REQUIRE(freed == 3);
}

TEST_CASE("namespace pin visible path boundaries and owning references", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        {
            namespace_epoch epoch;
            auto table = make_pin_table();
            auto object = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
            std::string longest(EBPF_MAX_PIN_PATH_LENGTH - 1, 'x');
            auto path = path_string(longest);
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &path, object.get()) == EBPF_SUCCESS);
            ebpf_core_object_t* found = nullptr;
            REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_a, &path, &found) == EBPF_SUCCESS);
            EBPF_OBJECT_RELEASE_REFERENCE(found);
            std::string invalid(EBPF_MAX_PIN_PATH_LENGTH, 'x');
            auto invalid_path = path_string(invalid);
            REQUIRE(
                ebpf_pinning_table_insert(table.get(), &namespace_a, &invalid_path, object.get()) ==
                EBPF_INVALID_ARGUMENT);
            cxplat_utf8_string_t empty = CXPLAT_UTF8_STRING_FROM_CONST_STRING("");
            REQUIRE(
                ebpf_pinning_table_insert(table.get(), &namespace_a, &empty, object.get()) == EBPF_INVALID_ARGUMENT);
            cxplat_utf8_string_t embedded = CXPLAT_UTF8_STRING_FROM_CONST_STRING("a\0b");
            REQUIRE(
                ebpf_pinning_table_insert(table.get(), &namespace_a, &embedded, object.get()) == EBPF_INVALID_ARGUMENT);
            cxplat_utf8_string_t second = CXPLAT_UTF8_STRING_FROM_CONST_STRING("second");
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &second, object.get()) == EBPF_SUCCESS);
            REQUIRE(object->pinned_path_count == 2);
            object.reset();
            REQUIRE(freed == 0);
            REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_b, &path) == EBPF_KEY_NOT_FOUND);
            REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &path) == EBPF_SUCCESS);
            REQUIRE(freed == 0);
            REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &second) == EBPF_SUCCESS);
        }
        ebpf_epoch_synchronize();
    }
    REQUIRE(freed == 1);
}

TEST_CASE("namespace pin snapshot namespace and type matrix", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto table = make_pin_table();
        std::vector<object_ptr> objects;
        for (const auto& namespace_id : namespaces) {
            for (const auto& type : object_types) {
                objects.push_back(make_object(namespace_id, type, freed));
                std::string name = "type-" + std::to_string(type);
                auto path = path_string(name);
                REQUIRE(
                    ebpf_pinning_table_insert(table.get(), &namespace_id, &path, objects.back().get()) == EBPF_SUCCESS);
            }
        }
        for (const auto& namespace_id : namespaces) {
            for (const auto& type : object_types) {
                uint16_t count = 0;
                ebpf_pinning_entry_t* entries = nullptr;
                REQUIRE(
                    ebpf_pinning_table_enumerate_entries(table.get(), &namespace_id, type, &count, &entries) ==
                    EBPF_SUCCESS);
                REQUIRE(count == 1);
                REQUIRE(entries[0].object->type == type);
                REQUIRE(memcmp(&entries[0].object->namespace_id, &namespace_id, sizeof(GUID)) == 0);
                REQUIRE(entries[0].object->base.reference_count == 3);
                ebpf_pinning_entries_release(count, entries);
            }
        }
        table.reset();
        for (const auto& object : objects) {
            REQUIRE(object->pinned_path_count == 0);
            REQUIRE(object->base.reference_count == 1);
        }
    }
    REQUIRE(freed == 9);
}

TEST_CASE("namespace pin concurrent insert and snapshot lifetime", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        auto table = make_pin_table();
        std::array<object_ptr, 4> objects;
        {
            namespace_epoch epoch;
            for (size_t i = 0; i < objects.size(); i++) {
                objects[i] = make_object(i < 2 ? namespace_a : namespace_b, EBPF_OBJECT_MAP, freed);
            }
        }
        std::barrier start(4);
        std::array<ebpf_result_t, 4> results{};
        std::vector<std::thread> threads;
        cxplat_utf8_string_t path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("raced");
        for (size_t i = 0; i < objects.size(); i++) {
            threads.emplace_back([&, i]() {
                namespace_epoch epoch;
                start.arrive_and_wait();
                results[i] = ebpf_pinning_table_insert(
                    table.get(), i < 2 ? &namespace_a : &namespace_b, &path, objects[i].get());
            });
        }
        for (auto& thread : threads) {
            thread.join();
        }
        namespace_epoch epoch;
        for (size_t i = 0; i < 4; i += 2) {
            REQUIRE(
                ((results[i] == EBPF_SUCCESS && results[i + 1] == EBPF_OBJECT_ALREADY_EXISTS) ||
                 (results[i] == EBPF_OBJECT_ALREADY_EXISTS && results[i + 1] == EBPF_SUCCESS)));
            const GUID& namespace_id = i == 0 ? namespace_a : namespace_b;
            uint16_t count;
            ebpf_pinning_entry_t* entries;
            REQUIRE(
                ebpf_pinning_table_enumerate_entries(table.get(), &namespace_id, EBPF_OBJECT_MAP, &count, &entries) ==
                EBPF_SUCCESS);
            REQUIRE(count == 1);
            REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_id, &path) == EBPF_SUCCESS);
            objects[i].reset();
            objects[i + 1].reset();
            REQUIRE(memcmp(&entries[0].object->namespace_id, &namespace_id, sizeof(GUID)) == 0);
            ebpf_pinning_entries_release(count, entries);
        }
        auto a_object = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
        auto b_object = make_object(namespace_b, EBPF_OBJECT_MAP, freed);
        std::atomic<bool> valid = true;
        std::barrier mutate_start(3);
        threads.clear();
        for (auto* object : {a_object.get(), b_object.get()}) {
            threads.emplace_back([&, object]() {
                namespace_epoch worker_epoch;
                mutate_start.arrive_and_wait();
                for (size_t i = 0; i < 64; i++) {
                    if (ebpf_pinning_table_insert(table.get(), &object->namespace_id, &path, object) != EBPF_SUCCESS) {
                        valid.store(false);
                    }
                    std::this_thread::yield();
                    if (ebpf_pinning_table_delete(table.get(), &object->namespace_id, &path) != EBPF_SUCCESS) {
                        valid.store(false);
                    }
                }
            });
        }
        threads.emplace_back([&]() {
            namespace_epoch worker_epoch;
            mutate_start.arrive_and_wait();
            for (size_t i = 0; i < 64; i++) {
                for (const GUID* namespace_id : {&namespace_a, &namespace_b}) {
                    ebpf_core_object_t* found = nullptr;
                    auto result = ebpf_pinning_table_find(table.get(), namespace_id, &path, &found);
                    if (result == EBPF_SUCCESS) {
                        if (found == nullptr || memcmp(&found->namespace_id, namespace_id, sizeof(GUID)) != 0) {
                            valid.store(false);
                        }
                        EBPF_OBJECT_RELEASE_REFERENCE(found);
                    } else if (result != EBPF_KEY_NOT_FOUND) {
                        valid.store(false);
                    }
                    uint16_t count = 0;
                    ebpf_pinning_entry_t* entries = nullptr;
                    result = ebpf_pinning_table_enumerate_entries(
                        table.get(), namespace_id, EBPF_OBJECT_MAP, &count, &entries);
                    if (result != EBPF_SUCCESS || count > 1) {
                        valid.store(false);
                    }
                    std::this_thread::yield();
                    for (uint16_t index = 0; index < count; index++) {
                        if (memcmp(&entries[index].object->namespace_id, namespace_id, sizeof(GUID)) != 0) {
                            valid.store(false);
                        }
                    }
                    ebpf_pinning_entries_release(count, entries);
                }
            }
        });
        for (auto& thread : threads) {
            thread.join();
        }
        REQUIRE(valid.load());
        REQUIRE(a_object->base.reference_count == 1);
        REQUIRE(b_object->base.reference_count == 1);
        REQUIRE(a_object->pinned_path_count == 0);
        REQUIRE(b_object->pinned_path_count == 0);
    }
    REQUIRE(freed == 6);
}

TEST_CASE("namespace constructors publish immutable ownership", "[namespace][namespace_objects]")
{
    _ebpf_core_initializer core;
    core.initialize();
    program_info_provider_t provider;
    REQUIRE(provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    namespace_epoch epoch;
    std::set<ebpf_id_t> ids;
    for (const auto& namespace_id : namespaces) {
        auto map = make_map(namespace_id);
        auto program = make_program(namespace_id);
        auto link = make_link(namespace_id);
        std::array<ebpf_core_object_t*, 3> objects = {
            reinterpret_cast<ebpf_core_object_t*>(map.get()),
            reinterpret_cast<ebpf_core_object_t*>(program.get()),
            reinterpret_cast<ebpf_core_object_t*>(link.get())};
        for (auto* object : objects) {
            REQUIRE(ids.insert(object->id).second);
            REQUIRE(memcmp(&object->namespace_id, &namespace_id, sizeof(GUID)) == 0);
            ebpf_core_object_t* found = nullptr;
            REQUIRE(EBPF_OBJECT_REFERENCE_BY_ID(&namespace_id, object->id, object->type, &found) == EBPF_SUCCESS);
            REQUIRE(found == object);
            EBPF_OBJECT_RELEASE_REFERENCE(found);
        }
        ebpf_program_parameters_t parameters{EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE};
        ebpf_handle_t handle = ebpf_handle_invalid;
        REQUIRE(ebpf_program_create_and_initialize(&namespace_id, &parameters, &handle) == EBPF_SUCCESS);
        ebpf_core_object_t* found = nullptr;
        REQUIRE(EBPF_OBJECT_REFERENCE_BY_HANDLE(handle, EBPF_OBJECT_PROGRAM, &found) == EBPF_SUCCESS);
        REQUIRE(memcmp(&found->namespace_id, &namespace_id, sizeof(GUID)) == 0);
        EBPF_OBJECT_RELEASE_REFERENCE(found);
        REQUIRE(ebpf_handle_close(handle) == EBPF_SUCCESS);
    }
}

TEST_CASE("namespace pin visible count is checked before snapshot allocation", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto object = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
        auto table = make_pin_table();
        for (uint32_t i = 0; i < UINT16_MAX; i++) {
            std::string name = "pin-" + std::to_string(i);
            auto path = path_string(name);
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &path, object.get()) == EBPF_SUCCESS);
        }
        uint16_t count = 0;
        ebpf_pinning_entry_t* entries = nullptr;
        REQUIRE(
            ebpf_pinning_table_enumerate_entries(table.get(), &namespace_a, EBPF_OBJECT_MAP, &count, &entries) ==
            EBPF_SUCCESS);
        REQUIRE(count == UINT16_MAX);
        ebpf_pinning_entries_release(count, entries);
        cxplat_utf8_string_t extra = CXPLAT_UTF8_STRING_FROM_CONST_STRING("overflow");
        REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &extra, object.get()) == EBPF_SUCCESS);
        REQUIRE(object->pinned_path_count == UINT16_MAX + 1);
        count = 42;
        entries = reinterpret_cast<ebpf_pinning_entry_t*>(1);
        REQUIRE(
            ebpf_pinning_table_enumerate_entries(table.get(), &namespace_a, EBPF_OBJECT_MAP, &count, &entries) ==
            EBPF_ARITHMETIC_OVERFLOW);
        REQUIRE(count == 0);
        REQUIRE(entries == nullptr);
        REQUIRE(
            ebpf_pinning_table_enumerate_entries(table.get(), &namespace_b, EBPF_OBJECT_MAP, &count, &entries) ==
            EBPF_SUCCESS);
        REQUIRE(count == 0);
        REQUIRE(entries == nullptr);
        REQUIRE(
            ebpf_pinning_table_enumerate_entries(table.get(), &namespace_a, EBPF_OBJECT_PROGRAM, &count, &entries) ==
            EBPF_SUCCESS);
        REQUIRE(count == 0);
        REQUIRE(entries == nullptr);
        table.reset();
        REQUIRE(object->pinned_path_count == 0);
        REQUIRE(object->base.reference_count == 1);
        REQUIRE(object->base.user_reference_count == 0);
    }
    REQUIRE(freed == 1);
}

TEST_CASE("namespace ID publication and removal race", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        std::barrier start(2);
        std::atomic<bool> done = false;
        std::atomic<bool> valid = true;
        std::atomic<ebpf_id_t> latest = 0;
        std::thread producer([&]() {
            start.arrive_and_wait();
            for (size_t i = 0; i < 256; i++) {
                namespace_epoch epoch;
                auto object = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
                latest.store(object->id);
                std::this_thread::yield();
            }
            done.store(true);
        });
        std::thread observer([&]() {
            start.arrive_and_wait();
            do {
                namespace_epoch epoch;
                ebpf_core_object_t* found = nullptr;
                auto result = EBPF_OBJECT_REFERENCE_BY_ID(&namespace_a, latest.load(), EBPF_OBJECT_MAP, &found);
                if (result == EBPF_SUCCESS) {
                    if (found == nullptr || memcmp(&found->namespace_id, &namespace_a, sizeof(GUID)) != 0) {
                        valid.store(false);
                    }
                    EBPF_OBJECT_RELEASE_REFERENCE(found);
                } else if (result != EBPF_KEY_NOT_FOUND || found != nullptr) {
                    valid.store(false);
                }
                ebpf_id_t next;
                if (ebpf_object_get_next_id(&namespace_default, 0, EBPF_OBJECT_MAP, &next) != EBPF_NO_MORE_KEYS) {
                    valid.store(false);
                }
                EBPF_OBJECT_REFERENCE_NEXT_OBJECT(&namespace_a, nullptr, EBPF_OBJECT_MAP, &found);
                if (found != nullptr) {
                    if (memcmp(&found->namespace_id, &namespace_a, sizeof(GUID)) != 0) {
                        valid.store(false);
                    }
                    EBPF_OBJECT_RELEASE_REFERENCE(found);
                }
            } while (!done.load());
        });
        producer.join();
        observer.join();
        REQUIRE(valid.load());
    }
    REQUIRE(freed == 256);
}

TEST_CASE("namespace graph edges validate immutable owners", "[namespace][namespace_objects]")
{
    _test_helper_end_to_end end_to_end;
    end_to_end.initialize();
    program_info_provider_t provider;
    REQUIRE(provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    namespace_epoch epoch;
    for (const auto& owner : namespaces) {
        for (const auto& candidate : namespaces) {
            bool same = memcmp(&owner, &candidate, sizeof(GUID)) == 0;
            auto expected = same ? EBPF_SUCCESS : EBPF_INVALID_ARGUMENT;
            auto map = make_map(candidate);
            auto program = make_program(owner);
            auto* map_object = reinterpret_cast<ebpf_core_object_t*>(map.get());
            REQUIRE(ebpf_map_associate_program(map.get(), program.get()) == expected);
            auto* maps = map.get();
            REQUIRE(ebpf_program_associate_maps(program.get(), &maps, 1) == expected);
            REQUIRE(map_object->base.reference_count == (same ? 2 : 1));
            auto bound_program = make_program(owner);
            REQUIRE(ebpf_program_associate_additional_map(bound_program.get(), map.get()) == expected);
            REQUIRE(map_object->base.reference_count == (same ? 3 : 1));
            auto link = make_link(owner);
            auto candidate_program = make_program(candidate);
            REQUIRE(ebpf_link_attach_program(link.get(), candidate_program.get()) == expected);
            ebpf_link_detach_program(link.get());
            namespace_handle inner_handle(map_object);
            for (auto type : std::array<ebpf_map_type_t, 2>{BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS}) {
                cxplat_utf8_string_t name{};
                ebpf_map_definition_in_memory_t definition{type, sizeof(uint32_t), sizeof(ebpf_id_t), 4};
                ebpf_map_t* outer = nullptr;
                REQUIRE(ebpf_map_create(&owner, &name, &definition, inner_handle.get(), &outer) == expected);
                map_ptr outer_map(outer);
                if (same) {
                    auto foreign = make_map(owner == namespace_a ? namespace_b : namespace_a);
                    namespace_handle foreign_handle(reinterpret_cast<ebpf_core_object_t*>(foreign.get()));
                    uint32_t key = 0;
                    REQUIRE(
                        ebpf_map_update_entry_with_handle(
                            outer_map.get(),
                            sizeof(key),
                            reinterpret_cast<uint8_t*>(&key),
                            inner_handle.get(),
                            EBPF_ANY) == EBPF_SUCCESS);
                    REQUIRE(
                        ebpf_map_update_entry_with_handle(
                            outer_map.get(),
                            sizeof(key),
                            reinterpret_cast<uint8_t*>(&key),
                            foreign_handle.get(),
                            EBPF_ANY) == EBPF_INVALID_ARGUMENT);
                    ebpf_id_t value = 0;
                    REQUIRE(
                        ebpf_map_find_entry(
                            outer_map.get(),
                            sizeof(key),
                            reinterpret_cast<uint8_t*>(&key),
                            sizeof(value),
                            reinterpret_cast<uint8_t*>(&value),
                            0) == EBPF_SUCCESS);
                    REQUIRE(value == map_object->id);
                }
            }
            auto program_array = make_map(owner, BPF_MAP_TYPE_PROG_ARRAY);
            namespace_handle program_handle(reinterpret_cast<ebpf_core_object_t*>(candidate_program.get()));
            uint32_t key = 0;
            REQUIRE(
                ebpf_map_update_entry_with_handle(
                    program_array.get(),
                    sizeof(key),
                    reinterpret_cast<uint8_t*>(&key),
                    program_handle.get(),
                    EBPF_ANY) == expected);
        }
    }
}

TEST_CASE("namespace handles remain neutral and mixed graph rejection is atomic", "[namespace][namespace_objects]")
{
    _ebpf_core_initializer core;
    core.initialize();
    program_info_provider_t provider;
    REQUIRE(provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    namespace_epoch epoch;
    auto a_map = make_map(namespace_a);
    auto b_map = make_map(namespace_b);
    auto program = make_program(namespace_a);
    auto* a_object = reinterpret_cast<ebpf_core_object_t*>(a_map.get());
    namespace_handle handle(a_object);
    ebpf_core_object_t* resolved = nullptr;
    REQUIRE(EBPF_OBJECT_REFERENCE_BY_HANDLE(handle.get(), EBPF_OBJECT_MAP, &resolved) == EBPF_SUCCESS);
    REQUIRE(resolved == a_object);
    uint32_t key = 0;
    uint32_t value = 42;
    REQUIRE(
        ebpf_map_update_entry(
            reinterpret_cast<ebpf_map_t*>(resolved),
            sizeof(key),
            reinterpret_cast<uint8_t*>(&key),
            sizeof(value),
            reinterpret_cast<uint8_t*>(&value),
            EBPF_ANY,
            0) == EBPF_SUCCESS);
    value = 0;
    REQUIRE(
        ebpf_map_find_entry(
            reinterpret_cast<ebpf_map_t*>(resolved),
            sizeof(key),
            reinterpret_cast<uint8_t*>(&key),
            sizeof(value),
            reinterpret_cast<uint8_t*>(&value),
            0) == EBPF_SUCCESS);
    REQUIRE(value == 42);
    REQUIRE(
        ebpf_map_delete_entry(
            reinterpret_cast<ebpf_map_t*>(resolved), sizeof(key), reinterpret_cast<uint8_t*>(&key), 0) == EBPF_SUCCESS);
    EBPF_OBJECT_RELEASE_REFERENCE(resolved);
    auto b_link = make_link(namespace_b);
    REQUIRE(ebpf_link_attach_program(b_link.get(), program.get()) == EBPF_INVALID_ARGUMENT);
    ebpf_map_t* mixed_maps[] = {a_map.get(), b_map.get()};
    REQUIRE(ebpf_program_associate_maps(program.get(), mixed_maps, 2) == EBPF_INVALID_ARGUMENT);
    REQUIRE(a_object->base.reference_count == 2);
    auto* map = a_map.get();
    REQUIRE(ebpf_program_associate_maps(program.get(), &map, 1) == EBPF_SUCCESS);
}

TEST_CASE("namespace link handle detach and global teardown", "[namespace][namespace_objects]")
{
    _test_helper_end_to_end end_to_end;
    end_to_end.initialize();
    program_info_provider_t provider;
    REQUIRE(provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
    REQUIRE(hook.initialize() == EBPF_SUCCESS);
    namespace_epoch epoch;
    std::vector<program_ptr> programs;
    std::vector<link_ptr> links;
    auto program_id = [](ebpf_link_t* link) {
        bpf_link_info info{};
        uint16_t size = sizeof(info);
        REQUIRE(ebpf_link_get_info(link, reinterpret_cast<uint8_t*>(&info), &size) == EBPF_SUCCESS);
        return info.prog_id;
    };
    for (size_t i = 0; i < namespaces.size(); i++) {
        programs.push_back(make_program(namespaces[i]));
        ebpf_link_t* link = nullptr;
        uint32_t context = static_cast<uint32_t>(i);
        REQUIRE(
            ebpf_link_create(
                &namespaces[i],
                EBPF_ATTACH_TYPE_SAMPLE,
                reinterpret_cast<uint8_t*>(&context),
                sizeof(context),
                &link) == EBPF_SUCCESS);
        links.emplace_back(link);
        REQUIRE(ebpf_link_attach_program(link, programs.back().get()) == EBPF_SUCCESS);
        REQUIRE(program_id(link) != 0);
    }
    auto extra = make_link(namespace_a);
    REQUIRE(ebpf_link_attach_program(extra.get(), programs[1].get()) == EBPF_SUCCESS);
    namespace_handle handle(reinterpret_cast<ebpf_core_object_t*>(extra.get()));
    ebpf_core_object_t* held = nullptr;
    REQUIRE(EBPF_OBJECT_REFERENCE_BY_HANDLE(handle.get(), EBPF_OBJECT_LINK, &held) == EBPF_SUCCESS);
    ebpf_link_detach_program(reinterpret_cast<ebpf_link_t*>(held));
    EBPF_OBJECT_RELEASE_REFERENCE(held);
    REQUIRE(program_id(extra.get()) == 0);
    GUID unrelated{};
    unrelated.Data1 = 0xabcdef01;
    ebpf_link_terminate();
    for (const auto& link : links) {
        REQUIRE(program_id(link.get()) == 0);
    }
}

TEST_CASE("namespace_NU14_publication_barrier", "[namespace][namespace_objects]")
{
    _ebpf_core_initializer core;
    core.initialize();
    program_info_provider_t provider;
    REQUIRE(provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    for (const auto& owner : namespaces) {
        for (const auto& type : object_types) {
            namespace_operation_gate gate(EBPF_OBJECT_TEST_BEFORE_PUBLICATION);
            namespace_callback_scope callback(namespace_operation_gate::callback, &gate);
            object_ptr created;
            ebpf_result_t creation = EBPF_INVALID_STATE;
            std::jthread creator([&]() {
                namespace_epoch epoch;
                switch (type) {
                case EBPF_OBJECT_MAP: {
                    cxplat_utf8_string_t name{};
                    ebpf_map_definition_in_memory_t definition{
                        BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};
                    ebpf_map_t* map = nullptr;
                    creation = ebpf_map_create(&owner, &name, &definition, ebpf_handle_invalid, &map);
                    created.reset(reinterpret_cast<ebpf_core_object_t*>(map));
                    break;
                }
                case EBPF_OBJECT_PROGRAM: {
                    ebpf_program_parameters_t parameters{EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE};
                    ebpf_program_t* program = nullptr;
                    creation = ebpf_program_create(&owner, &parameters, &program);
                    created.reset(reinterpret_cast<ebpf_core_object_t*>(program));
                    break;
                }
                case EBPF_OBJECT_LINK: {
                    ebpf_link_t* link = nullptr;
                    creation = ebpf_link_create(&owner, EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &link);
                    created.reset(reinterpret_cast<ebpf_core_object_t*>(link));
                    break;
                }
                default:
                    break;
                }
                gate.complete();
            });
            namespace_gate_release unblock(gate);
            REQUIRE(gate.wait());
            namespace_epoch epoch;
            REQUIRE(gate.observed->namespace_id == owner);
            REQUIRE(gate.observed->type == type);
            ebpf_id_t id = gate.observed->id;
            for (const auto& scope : namespaces) {
                ebpf_core_object_t* found = nullptr;
                REQUIRE(EBPF_OBJECT_REFERENCE_BY_ID(&scope, id, type, &found) == EBPF_KEY_NOT_FOUND);
                REQUIRE(found == nullptr);
                ebpf_id_t next = 0;
                REQUIRE(ebpf_object_get_next_id(&scope, 0, type, &next) == EBPF_NO_MORE_KEYS);
            }
            gate.release();
            creator.join();
            REQUIRE(creation == EBPF_SUCCESS);
            REQUIRE(created != nullptr);
            REQUIRE(created->id == id);
            for (const auto& scope : namespaces) {
                ebpf_core_object_t* found = nullptr;
                bool matches = scope == owner;
                REQUIRE(
                    EBPF_OBJECT_REFERENCE_BY_ID(&scope, id, type, &found) ==
                    (matches ? EBPF_SUCCESS : EBPF_KEY_NOT_FOUND));
                REQUIRE(found == (matches ? created.get() : nullptr));
                EBPF_OBJECT_RELEASE_REFERENCE(found);
            }
            REQUIRE(created->base.reference_count == 1);
            created.reset();
        }
    }
}

TEST_CASE("namespace_NU17_try_reference_and_epoch_barrier", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    std::binary_semaphore lookup_freed{0};
    std::binary_semaphore traversal_freed{0};
    {
        _ebpf_core_initializer core;
        core.initialize();
        object_ptr hidden;
        {
            namespace_epoch epoch;
            hidden = make_object(namespace_b, EBPF_OBJECT_MAP, freed);
        }
        size_t expected_freed = 0;
        for (bool traversal : {false, true}) {
            auto& free_signal = traversal ? traversal_freed : lookup_freed;
            object_ptr object;
            {
                namespace_epoch epoch;
                object = make_object(namespace_a, EBPF_OBJECT_MAP, freed, nullptr, &free_signal);
            }
            ebpf_id_t id = object->id;
            namespace_operation_gate gate(EBPF_OBJECT_TEST_BEFORE_TRY_REFERENCE, id);
            namespace_callback_scope callback(namespace_operation_gate::callback, &gate);
            ebpf_result_t lookup = EBPF_INVALID_STATE;
            bool acquired = false;
            std::jthread reader([&]() {
                namespace_epoch epoch;
                ebpf_core_object_t* found = nullptr;
                if (traversal) {
                    EBPF_OBJECT_REFERENCE_NEXT_OBJECT(&namespace_a, nullptr, EBPF_OBJECT_MAP, &found);
                } else {
                    lookup = EBPF_OBJECT_REFERENCE_BY_ID(&namespace_a, id, EBPF_OBJECT_MAP, &found);
                }
                acquired = found != nullptr;
                EBPF_OBJECT_RELEASE_REFERENCE(found);
                gate.complete();
            });
            namespace_gate_release unblock(gate);
            REQUIRE(gate.wait());
            {
                namespace_epoch epoch;
                object.reset();
                REQUIRE(gate.observed->base.reference_count == 0);
                REQUIRE(gate.observed->namespace_id == namespace_a);
                REQUIRE(freed == expected_freed);
                ebpf_core_object_t* found = nullptr;
                REQUIRE(EBPF_OBJECT_REFERENCE_BY_ID(&namespace_a, id, EBPF_OBJECT_MAP, &found) == EBPF_KEY_NOT_FOUND);
                REQUIRE(found == nullptr);
            }
            REQUIRE(freed == expected_freed);
            gate.release();
            reader.join();
            REQUIRE_FALSE(acquired);
            if (!traversal) {
                REQUIRE(lookup == EBPF_KEY_NOT_FOUND);
            }
            ebpf_epoch_synchronize();
            REQUIRE(free_signal.try_acquire_for(std::chrono::seconds(10)));
            expected_freed++;
            REQUIRE(freed == expected_freed);
            REQUIRE(hidden->base.reference_count == 1);
        }
    }
    REQUIRE(freed == 3);
}

TEST_CASE("namespace_NU36_snapshot_delete_epoch_schedule", "[namespace][namespace_objects]")
{
    std::atomic<size_t> freed = 0;
    std::binary_semaphore visible_freed{0};
    {
        _ebpf_core_initializer core;
        core.initialize();
        auto table = make_pin_table();
        object_ptr visible;
        object_ptr hidden;
        cxplat_utf8_string_t path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("scheduled");
        {
            namespace_epoch epoch;
            visible = make_object(namespace_a, EBPF_OBJECT_MAP, freed, nullptr, &visible_freed);
            hidden = make_object(namespace_b, EBPF_OBJECT_MAP, freed);
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &path, visible.get()) == EBPF_SUCCESS);
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_b, &path, hidden.get()) == EBPF_SUCCESS);
        }
        namespace_operation_gate gate(EBPF_OBJECT_TEST_BEFORE_TRY_REFERENCE);
        ebpf_result_t snapshot = EBPF_INVALID_STATE;
        std::atomic<bool> valid = false;
        std::jthread reader([&]() {
            uint16_t count = 0;
            ebpf_pinning_entry_t* entries = nullptr;
            {
                namespace_epoch epoch;
                snapshot =
                    ebpf_pinning_table_enumerate_entries(table.get(), &namespace_a, EBPF_OBJECT_MAP, &count, &entries);
            }
            if (snapshot == EBPF_SUCCESS && count == 1) {
                (void)namespace_operation_gate::callback(
                    EBPF_OBJECT_TEST_BEFORE_TRY_REFERENCE, entries[0].object, &gate);
                valid.store(
                    entries[0].object->namespace_id == namespace_a && entries[0].object->pinned_path_count == 0 &&
                    entries[0].object->base.user_reference_count == 0 && entries[0].object->base.reference_count == 1 &&
                    entries[0].path.length == path.length &&
                    memcmp(entries[0].path.value, path.value, path.length) == 0);
            }
            {
                namespace_epoch epoch;
                ebpf_pinning_entries_release(count, entries);
            }
            gate.complete();
        });
        namespace_gate_release unblock(gate);
        REQUIRE(gate.wait());
        REQUIRE(snapshot == EBPF_SUCCESS);
        {
            namespace_epoch epoch;
            REQUIRE(ebpf_pinning_table_delete(table.get(), &namespace_a, &path) == EBPF_SUCCESS);
            visible.reset();
            ebpf_core_object_t* found = nullptr;
            REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_a, &path, &found) == EBPF_KEY_NOT_FOUND);
            REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_b, &path, &found) == EBPF_SUCCESS);
            REQUIRE(found == hidden.get());
            EBPF_OBJECT_RELEASE_REFERENCE(found);
        }
        ebpf_epoch_synchronize();
        REQUIRE(freed == 0);
        REQUIRE(gate.observed->base.reference_count == 1);
        gate.release();
        reader.join();
        REQUIRE(valid.load());
        ebpf_epoch_synchronize();
        REQUIRE(visible_freed.try_acquire_for(std::chrono::seconds(10)));
        REQUIRE(freed == 1);
    }
    REQUIRE(freed == 2);
}

#if defined(CXPLAT_DEBUGGING_FEATURES_ENABLED)
TEST_CASE("namespace_NU33_cxplat_fault_retry_and_unwind", "[namespace][namespace_objects]")
{
    if (cxplat_fault_injection_is_enabled()) {
        WARN("An external fault-injection campaign owns the fault log; do not reset its state.");
        return;
    }
    namespace_fault_session faults;
    std::atomic<size_t> freed = 0;
    {
        _ebpf_core_initializer core;
        core.initialize();
        namespace_epoch epoch;
        auto object = make_object(namespace_a, EBPF_OBJECT_MAP, freed);
        auto hidden = make_object(namespace_b, EBPF_OBJECT_MAP, freed);
        for (auto point : {EBPF_OBJECT_TEST_PIN_TABLE_ALLOCATION, EBPF_OBJECT_TEST_PIN_HASH_ALLOCATION}) {
            cxplat_fault_injection_reset();
            namespace_fault_target target{point};
            namespace_callback_scope callback(namespace_fault_target::callback, &target);
            bool succeeded = false;
            for (size_t attempt = 0; attempt < 8; attempt++) {
                target.observed = 0;
                ebpf_pinning_table_t* output = nullptr;
                target.active = true;
                auto result = ebpf_pinning_table_allocate(&output);
                target.active = false;
                pin_table_ptr table(output, ebpf_pinning_table_free);
                if (result == EBPF_SUCCESS) {
                    REQUIRE(output != nullptr);
                    succeeded = true;
                    break;
                }
                REQUIRE(result == EBPF_NO_MEMORY);
                REQUIRE(output == nullptr);
            }
            REQUIRE(succeeded);
            REQUIRE(target.faults == 1);
        }
        cxplat_utf8_string_t path = CXPLAT_UTF8_STRING_FROM_CONST_STRING("failed-insert");
        for (auto point : {EBPF_OBJECT_TEST_PIN_ENTRY_ALLOCATION, EBPF_OBJECT_TEST_PIN_HASH_ALLOCATION}) {
            bool exhausted = false;
            size_t injected = 0;
            for (size_t ordinal = 1; ordinal <= 16; ordinal++) {
                auto table = make_pin_table();
                REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_b, &path, hidden.get()) == EBPF_SUCCESS);
                cxplat_fault_injection_reset();
                namespace_fault_target target{point, ordinal};
                namespace_callback_scope callback(namespace_fault_target::callback, &target);
                bool succeeded = false;
                for (size_t attempt = 0; attempt < 8; attempt++) {
                    target.observed = 0;
                    target.active = true;
                    auto result = ebpf_pinning_table_insert(table.get(), &namespace_a, &path, object.get());
                    target.active = false;
                    if (result == EBPF_SUCCESS) {
                        succeeded = true;
                        break;
                    }
                    REQUIRE(result == EBPF_NO_MEMORY);
                    REQUIRE(object->base.reference_count == 1);
                    REQUIRE(object->base.user_reference_count == 0);
                    REQUIRE(object->pinned_path_count == 0);
                    ebpf_core_object_t* found = nullptr;
                    REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_a, &path, &found) == EBPF_KEY_NOT_FOUND);
                    REQUIRE(found == nullptr);
                    REQUIRE(ebpf_pinning_table_find(table.get(), &namespace_b, &path, &found) == EBPF_SUCCESS);
                    REQUIRE(found == hidden.get());
                    EBPF_OBJECT_RELEASE_REFERENCE(found);
                    REQUIRE(hidden->base.reference_count == 2);
                    REQUIRE(hidden->pinned_path_count == 1);
                }
                REQUIRE(succeeded);
                REQUIRE(target.faults <= 1);
                injected += target.faults;
                REQUIRE(object->base.reference_count == 2);
                REQUIRE(object->base.user_reference_count == 1);
                REQUIRE(object->pinned_path_count == 1);
                table.reset();
                REQUIRE(object->base.reference_count == 1);
                REQUIRE(object->base.user_reference_count == 0);
                REQUIRE(object->pinned_path_count == 0);
                REQUIRE(hidden->base.reference_count == 1);
                if (target.faults == 0) {
                    REQUIRE(target.observed < ordinal);
                    exhausted = true;
                    break;
                }
            }
            REQUIRE(exhausted);
            REQUIRE(injected > 0);
        }
        auto table = make_pin_table();
        for (auto text : {"first", "second", "third"}) {
            std::string name(text);
            auto pin = path_string(name);
            REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_a, &pin, object.get()) == EBPF_SUCCESS);
        }
        REQUIRE(ebpf_pinning_table_insert(table.get(), &namespace_b, &path, hidden.get()) == EBPF_SUCCESS);
        for (auto point : {EBPF_OBJECT_TEST_PIN_SNAPSHOT_ALLOCATION, EBPF_OBJECT_TEST_PIN_SNAPSHOT_PATH_ALLOCATION}) {
            size_t allocations = point == EBPF_OBJECT_TEST_PIN_SNAPSHOT_PATH_ALLOCATION ? 3 : 1;
            for (size_t ordinal = 1; ordinal <= allocations; ordinal++) {
                cxplat_fault_injection_reset();
                namespace_fault_target target{point, ordinal};
                namespace_callback_scope callback(namespace_fault_target::callback, &target);
                bool succeeded = false;
                for (size_t attempt = 0; attempt < 8; attempt++) {
                    target.observed = 0;
                    uint16_t count = 42;
                    ebpf_pinning_entry_t* entries = nullptr;
                    target.active = true;
                    auto result = ebpf_pinning_table_enumerate_entries(
                        table.get(), &namespace_a, EBPF_OBJECT_MAP, &count, &entries);
                    target.active = false;
                    if (result == EBPF_SUCCESS) {
                        REQUIRE(count == 3);
                        REQUIRE(object->base.reference_count == 7);
                        ebpf_pinning_entries_release(count, entries);
                        succeeded = true;
                        break;
                    }
                    REQUIRE(result == EBPF_NO_MEMORY);
                    REQUIRE(count == 0);
                    REQUIRE(entries == nullptr);
                    REQUIRE(object->base.reference_count == 4);
                    REQUIRE(object->base.user_reference_count == 3);
                    REQUIRE(object->pinned_path_count == 3);
                    REQUIRE(hidden->base.reference_count == 2);
                    REQUIRE(hidden->pinned_path_count == 1);
                }
                REQUIRE(succeeded);
                REQUIRE(target.faults == 1);
                REQUIRE(object->base.reference_count == 4);
            }
        }
        table.reset();
        REQUIRE(object->base.reference_count == 1);
        REQUIRE(hidden->base.reference_count == 1);
        REQUIRE(object->pinned_path_count == 0);
        REQUIRE(hidden->pinned_path_count == 0);
    }
    REQUIRE(freed == 2);
}
#endif
