// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "ebpf_protocol.h"
#include "ebpf_shared_framework.h"
#include "ebpf_windows.h"
#include "sample_ext_helpers.h"

#if defined(EBPF_NAMESPACE_UNIT_TEST)
#include "api_internal.h"
#include "device_helper.hpp"
#include "ebpf_core.h"
#include "ebpf_namespace.h"
#include "mock.h"
#include "namespaces.h"
#include "platform.h"
#include "test_helper.hpp"
#endif

#include <array>
#include <atomic>
#include <barrier>
#include <filesystem>
#include <io.h>
#include <memory>
#include <thread>
#include <vector>
#include <winioctl.h>

namespace {
const GUID default_namespace{};
const GUID namespace_a{0x2d0fcaf1, 0x5ca8, 0x4329, {0xb7, 0x4c, 0xac, 0xcb, 0xe7, 0xa2, 0xaa, 0x01}};
const GUID namespace_b{0x2d0fcaf1, 0x5ca8, 0x4329, {0xb7, 0x4c, 0xac, 0xcb, 0xe7, 0xa2, 0xaa, 0x02}};
const char pin_path[] = "BPF:\\thread_namespace_regression";

class namespace_fixture
{
  public:
    namespace_fixture()
    {
#if defined(EBPF_NAMESPACE_UNIT_TEST)
        helper.initialize();
#endif
        REQUIRE(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS);
    }
    ~namespace_fixture() { CHECK(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS); }

  private:
#if defined(EBPF_NAMESPACE_UNIT_TEST)
    _test_helper_libbpf helper;
#endif
};

class namespace_fd
{
  public:
    explicit namespace_fd(int value) : value(value) {}
    ~namespace_fd()
    {
        if (value >= 0) {
            CHECK(ebpf_close_fd(value) == EBPF_SUCCESS);
        }
    }
    namespace_fd(const namespace_fd&) = delete;
    namespace_fd&
    operator=(const namespace_fd&) = delete;
    int value;
};

GUID
selected_namespace()
{
    GUID value{};
    REQUIRE(ebpf_get_thread_namespace(&value) == EBPF_SUCCESS);
    return value;
}

int
create_map()
{
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "thread_ns", sizeof(uint32_t), sizeof(uint32_t), 2, nullptr);
    REQUIRE(fd > 0);
    return fd;
}

uint32_t
map_id(int fd)
{
    bpf_map_info info{};
    uint32_t size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(fd, &info, &size) == 0);
    return info.id;
}

struct thread_transport_cleanup
{
    ~thread_transport_cleanup()
    {
#if defined(EBPF_NAMESPACE_UNIT_TEST)
        clean_up_sync_device_handle();
#endif
    }
};

using namespace_object = std::unique_ptr<bpf_object, decltype(&bpf_object__close)>;

namespace_object
load_native_object()
{
#if defined(EBPF_NAMESPACE_UNIT_TEST)
    const char* file = "test_sample_ebpf_um.dll";
#else
    const char* file = "test_sample_ebpf.sys";
#endif
    namespace_object object(bpf_object__open(file), bpf_object__close);
    REQUIRE(object != nullptr);
    REQUIRE(bpf_object__load(object.get()) == 0);
    return object;
}

class namespace_control_file
{
  public:
    namespace_control_file()
    {
#if defined(EBPF_NAMESPACE_UNIT_TEST)
        handle =
            Platform::CreateFile(EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, 0);
#else
        handle = reinterpret_cast<ebpf_handle_t>(
            CreateFileW(EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
#endif
        REQUIRE(handle != ebpf_handle_invalid);
    }
    ~namespace_control_file()
    {
#if defined(EBPF_NAMESPACE_UNIT_TEST)
        CHECK(Platform::CloseHandle(handle));
#else
        CHECK(CloseHandle(reinterpret_cast<HANDLE>(handle)));
#endif
    }
    bool
    invoke(void* input, DWORD input_size, void* output, DWORD output_size)
    {
        constexpr DWORD ioctl = CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
#if defined(EBPF_NAMESPACE_UNIT_TEST)
        uint32_t returned = 0;
        return Platform::DeviceIoControl(handle, ioctl, input, input_size, output, output_size, &returned, nullptr);
#else
        DWORD returned = 0;
        return !!DeviceIoControl(
            reinterpret_cast<HANDLE>(handle), ioctl, input, input_size, output, output_size, &returned, nullptr);
#endif
    }
    void
    select(const GUID& guid)
    {
        ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, guid};
        REQUIRE(invoke(&request, sizeof(request), nullptr, 0));
    }
    GUID
    get()
    {
        ebpf_operation_get_namespace_request_t request{{sizeof(request), EBPF_OPERATION_GET_NAMESPACE}};
        ebpf_operation_get_namespace_reply_t reply{};
        REQUIRE(invoke(&request, sizeof(request), &reply, sizeof(reply)));
        REQUIRE(reply.header.length == sizeof(reply));
        REQUIRE(reply.header.id == EBPF_OPERATION_GET_NAMESPACE);
        return reply.namespace_id;
    }
    ebpf_handle_t
    create_map_handle(const ebpf_map_definition_in_memory_t& definition)
    {
        std::vector<uint8_t> bytes(offsetof(ebpf_operation_create_map_request_t, data));
        auto* request = reinterpret_cast<ebpf_operation_create_map_request_t*>(bytes.data());
        request->header = {static_cast<uint16_t>(bytes.size()), EBPF_OPERATION_CREATE_MAP};
        request->ebpf_map_definition = definition;
        request->inner_map_handle = ebpf_handle_invalid;
        ebpf_operation_create_map_reply_t reply{};
        REQUIRE(invoke(request, static_cast<DWORD>(bytes.size()), &reply, sizeof(reply)));
        return reply.handle;
    }
    uint32_t
    query_map_id(ebpf_handle_t object)
    {
        ebpf_operation_get_object_info_request_t query{};
        query.header = {sizeof(query), EBPF_OPERATION_GET_OBJECT_INFO};
        query.handle = object;
        std::vector<uint8_t> reply(offsetof(ebpf_operation_get_object_info_reply_t, info) + sizeof(bpf_map_info));
        REQUIRE(invoke(&query, sizeof(query), reply.data(), static_cast<DWORD>(reply.size())));
        bpf_map_info info{};
        memcpy(&info, reply.data() + offsetof(ebpf_operation_get_object_info_reply_t, info), sizeof(info));
        return info.id;
    }
    ebpf_handle_t handle;
};
} // namespace

TEST_CASE("thread namespace selection and argument contracts", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(selected_namespace() == default_namespace);
    REQUIRE(ebpf_set_thread_namespace(nullptr) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_get_thread_namespace(nullptr) == EBPF_INVALID_ARGUMENT);
    for (const GUID& value : {namespace_a, namespace_a, namespace_b, default_namespace}) {
        REQUIRE(ebpf_set_thread_namespace(&value) == EBPF_SUCCESS);
        REQUIRE(selected_namespace() == value);
    }
}

TEST_CASE("thread namespace starts default without parent inheritance", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    GUID initial{}, final{};
    ebpf_result_t get_result = EBPF_FAILED, set_result = EBPF_FAILED;
    std::jthread worker([&] {
        thread_transport_cleanup cleanup;
        get_result = ebpf_get_thread_namespace(&initial);
        set_result = ebpf_set_thread_namespace(&namespace_b);
        if (set_result == EBPF_SUCCESS) {
            (void)ebpf_get_thread_namespace(&final);
        }
    });
    worker.join();
    REQUIRE(get_result == EBPF_SUCCESS);
    REQUIRE(set_result == EBPF_SUCCESS);
    REQUIRE(initial == default_namespace);
    REQUIRE(final == namespace_b);
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE("thread namespace concurrent selection and ID isolation", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    struct worker_result
    {
        GUID selected{};
        ebpf_result_t status = EBPF_FAILED;
        int fd = -1;
    };
    std::array<worker_result, 2> results{};
    std::barrier ready(3);
    auto work = [&](size_t index, const GUID& expected) {
        thread_transport_cleanup cleanup;
        auto& result = results[index];
        result.status = ebpf_set_thread_namespace(&expected);
        if (result.status == EBPF_SUCCESS) {
            result.fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "thread_ns", 4, 4, 1, nullptr);
        }
        ready.arrive_and_wait();
        if (result.status == EBPF_SUCCESS) {
            result.status = ebpf_get_thread_namespace(&result.selected);
        }
    };
    std::jthread first(work, 0, std::cref(namespace_a));
    std::jthread second(work, 1, std::cref(namespace_b));
    ready.arrive_and_wait();
    first.join();
    second.join();
    namespace_fd a(results[0].fd), b(results[1].fd);
    REQUIRE(results[0].status == EBPF_SUCCESS);
    REQUIRE(results[1].status == EBPF_SUCCESS);
    REQUIRE(results[0].selected == namespace_a);
    REQUIRE(results[1].selected == namespace_b);
    REQUIRE(a.value > 0);
    REQUIRE(b.value > 0);
    const auto a_id = map_id(a.value), b_id = map_id(b.value);
    REQUIRE(a_id != b_id);
    REQUIRE(bpf_map_get_fd_by_id(a_id) < 0);
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd opened(bpf_map_get_fd_by_id(a_id));
    REQUIRE(opened.value > 0);
    REQUIRE(bpf_map_get_fd_by_id(b_id) < 0);
    uint32_t key = 0, value = 42, actual = 0;
    REQUIRE(bpf_map_update_elem(b.value, &key, &value, 0) == 0);
    REQUIRE(bpf_map_lookup_elem(b.value, &key, &actual) == 0);
    REQUIRE(actual == value);
}

TEST_CASE("thread namespace ID enumeration skips foreign objects", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    namespace_fd hidden_first(create_map());
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd visible_first(create_map());
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    namespace_fd hidden_middle(create_map());
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd visible_last(create_map());
    uint32_t next = 0;
    REQUIRE(bpf_map_get_next_id(0, &next) == 0);
    REQUIRE(next == map_id(visible_first.value));
    REQUIRE(bpf_map_get_next_id(next, &next) == 0);
    REQUIRE(next == map_id(visible_last.value));
    REQUIRE(bpf_map_get_next_id(next, &next) < 0);
}

TEST_CASE("thread namespace same-path pins and held fd lifetime", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd a(create_map());
    REQUIRE(bpf_obj_pin(a.value, pin_path) == 0);
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE(bpf_obj_get(pin_path) < 0);
    namespace_fd b(create_map());
    REQUIRE(bpf_obj_pin(b.value, pin_path) == 0);
    namespace_fd opened_b(bpf_obj_get(pin_path));
    REQUIRE(map_id(opened_b.value) == map_id(b.value));
    REQUIRE(ebpf_object_unpin(pin_path) == EBPF_SUCCESS);
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd opened_a(bpf_obj_get(pin_path));
    REQUIRE(map_id(opened_a.value) == map_id(a.value));
    REQUIRE(ebpf_object_unpin(pin_path) == EBPF_SUCCESS);
    REQUIRE(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS);
    uint32_t key = 0, value = 73, actual = 0;
    REQUIRE(bpf_map_update_elem(opened_a.value, &key, &value, 0) == 0);
    REQUIRE(bpf_map_lookup_elem(a.value, &key, &actual) == 0);
    REQUIRE(actual == value);
}

TEST_CASE("thread namespace pin enumeration grows replies without crossing scope", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    std::vector<std::unique_ptr<namespace_fd>> maps;
    std::vector<std::string> paths;
    struct pins_cleanup
    {
        std::vector<std::string>& paths;
        ~pins_cleanup()
        {
            auto result = ebpf_set_thread_namespace(&namespace_a);
            CHECK(result == EBPF_SUCCESS);
            if (result == EBPF_SUCCESS) {
                for (const auto& path : paths) {
                    CHECK(ebpf_object_unpin(path.c_str()) == EBPF_SUCCESS);
                }
            }
        }
    } cleanup{paths};
    for (size_t index = 0; index < 32; ++index) {
        maps.push_back(std::make_unique<namespace_fd>(create_map()));
        auto path = std::string("BPF:\\thread_namespace_") + std::string(160, 'x') + std::to_string(index);
        REQUIRE(bpf_obj_pin(maps.back()->value, path.c_str()) == 0);
        paths.push_back(path);
    }
    uint16_t count = 0;
    ebpf_map_info_t* info = nullptr;
    REQUIRE(ebpf_api_get_pinned_map_info(&count, &info) == EBPF_SUCCESS);
    ebpf_api_map_info_free(count, info);
    REQUIRE(count == maps.size());
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    count = 0;
    info = nullptr;
    REQUIRE(ebpf_api_get_pinned_map_info(&count, &info) == EBPF_SUCCESS);
    ebpf_api_map_info_free(count, info);
    REQUIRE(count == 0);
}

TEST_CASE("thread namespace wrapper pin status is selection neutral", "[namespace][thread_namespace][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    auto object = load_native_object();
    bpf_map* map = bpf_object__next_map(object.get(), nullptr);
    REQUIRE(map != nullptr);
    REQUIRE_FALSE(bpf_map__is_pinned(map));
    REQUIRE(bpf_map__pin(map, pin_path) == 0);
    for (const GUID& value : {namespace_b, default_namespace, namespace_a}) {
        REQUIRE(ebpf_set_thread_namespace(&value) == EBPF_SUCCESS);
        REQUIRE(bpf_map__is_pinned(map));
        if (value != namespace_a) {
            REQUIRE(bpf_map__pin(map, pin_path) < 0);
            REQUIRE(bpf_map__unpin(map, pin_path) < 0);
            REQUIRE(bpf_map__is_pinned(map));
        }
    }
    REQUIRE(bpf_map__unpin(map, pin_path) == 0);
    REQUIRE_FALSE(bpf_map__is_pinned(map));
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE_FALSE(bpf_map__is_pinned(map));
}

TEST_CASE("thread namespace retained graph handles compare owners not selection", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd inner(create_map());
    bpf_map_create_opts options{};
    options.sz = sizeof(options);
    options.inner_map_fd = inner.value;
    namespace_fd outer(bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "outer_ns", 4, 4, 1, &options));
    REQUIRE(outer.value > 0);
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    namespace_fd foreign(create_map());
    REQUIRE(bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "bad_outer", 4, 4, 1, &options) < 0);
    uint32_t key = 0;
    REQUIRE(bpf_map_update_elem(outer.value, &key, &inner.value, 0) == 0);
    REQUIRE(bpf_map_update_elem(outer.value, &key, &foreign.value, 0) < 0);
}

TEST_CASE("thread namespace pooled workers support both application policies", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    bool reset_between_jobs = GENERATE(true, false);
    for (const GUID& expected : {namespace_a, namespace_b, default_namespace}) {
        REQUIRE(ebpf_set_thread_namespace(&expected) == EBPF_SUCCESS);
        namespace_fd object(create_map());
        REQUIRE(selected_namespace() == expected);
        if (reset_between_jobs) {
            REQUIRE(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS);
            REQUIRE(selected_namespace() == default_namespace);
        }
    }
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd retained(create_map());
    REQUIRE(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS);
    REQUIRE(bpf_map_get_fd_by_id(map_id(retained.value)) < 0);
}

TEST_CASE(
    "thread namespace raw control files start independently and duplicates share scope",
    "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_control_file first, second;
    REQUIRE(first.get() == default_namespace);
    REQUIRE(second.get() == default_namespace);
    first.select(namespace_a);
    REQUIRE(second.get() == default_namespace);
    HANDLE duplicate = nullptr;
#if defined(EBPF_NAMESPACE_UNIT_TEST)
    ebpf_handle_t duplicate_handle = ebpf_handle_invalid;
    REQUIRE(Platform::DuplicateHandle(
        reinterpret_cast<ebpf_handle_t>(GetCurrentProcess()),
        first.handle,
        reinterpret_cast<ebpf_handle_t>(GetCurrentProcess()),
        &duplicate_handle,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS));
    duplicate = reinterpret_cast<HANDLE>(duplicate_handle);
#else
    REQUIRE(DuplicateHandle(
        GetCurrentProcess(),
        reinterpret_cast<HANDLE>(first.handle),
        GetCurrentProcess(),
        &duplicate,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS));
#endif
    namespace_control_file alias;
#if defined(EBPF_NAMESPACE_UNIT_TEST)
    REQUIRE(Platform::CloseHandle(alias.handle));
#else
    REQUIRE(CloseHandle(reinterpret_cast<HANDLE>(alias.handle)));
#endif
    alias.handle = reinterpret_cast<ebpf_handle_t>(duplicate);
    alias.select(namespace_b);
    REQUIRE(first.get() == namespace_b);
    REQUIRE(second.get() == default_namespace);
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE(
    "thread namespace native attachment and async execution preserve held handles",
    "[namespace][thread_namespace][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    auto object = load_native_object();
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE(bpf_program__attach(program) == nullptr);
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)> link(bpf_program__attach(program), bpf_link__destroy);
    REQUIRE(link != nullptr);
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE(bpf_link_detach(bpf_link__fd(link.get())) == 0);
    for (const GUID& guid : {namespace_b, default_namespace}) {
        REQUIRE(ebpf_set_thread_namespace(&guid) == EBPF_SUCCESS);
        sample_program_context_t context{};
        bpf_test_run_opts options{};
        options.sz = sizeof(options);
        options.repeat = 1;
        options.ctx_in = &context;
        options.ctx_size_in = sizeof(context);
        options.ctx_out = &context;
        options.ctx_size_out = sizeof(context);
        REQUIRE(bpf_prog_test_run_opts(bpf_program__fd(program), &options) == 0);
        REQUIRE(selected_namespace() == guid);
    }
}

#if defined(EBPF_NAMESPACE_UNIT_TEST)
namespace {
class ioctl_override
{
  public:
    ioctl_override() : original(device_io_control_handler) {}
    ~ioctl_override() { device_io_control_handler = original; }
    std::function<decltype(DeviceIoControl)> original;
};
} // namespace

TEST_CASE("thread namespace SET acknowledgement and failed reset retain TLS", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    uint32_t failure = GENERATE(uint32_t{ERROR_ACCESS_DENIED}, uint32_t{ERROR_SUCCESS});
    for (bool lost_reply : {false, true}) {
        {
            ioctl_override override;
            device_io_control_handler = [&](auto handle,
                                            auto code,
                                            auto input,
                                            auto input_size,
                                            auto output,
                                            auto output_size,
                                            auto returned,
                                            auto overlapped) {
                if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_SET_NAMESPACE) {
                    if (lost_reply) {
                        REQUIRE(override.original(
                            handle, code, input, input_size, output, output_size, returned, overlapped));
                    }
                    SetLastError(failure);
                    return FALSE;
                }
                return override.original(handle, code, input, input_size, output, output_size, returned, overlapped);
            };
            REQUIRE(
                ebpf_set_thread_namespace(&default_namespace) ==
                (failure == ERROR_SUCCESS ? EBPF_FAILED : EBPF_ACCESS_DENIED));
        }
        REQUIRE(selected_namespace() == namespace_a);
        namespace_fd map(create_map());
        REQUIRE(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS);
        REQUIRE(bpf_map_get_fd_by_id(map_id(map.value)) < 0);
        REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    }
}

TEST_CASE(
    "thread namespace cached pin query performs no IO even when binding is unavailable",
    "[namespace][thread_namespace][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    auto object = load_native_object();
    bpf_map* map = bpf_object__next_map(object.get(), nullptr);
    REQUIRE(map != nullptr);
    REQUIRE(bpf_map__pin(map, pin_path) == 0);
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    clean_up_sync_device_handle();
    {
        unsigned long calls = 0;
        ioctl_override override;
        device_io_control_handler = [&](auto, auto, auto, auto, auto, auto, auto, auto) {
            ++calls;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        };
        REQUIRE(bpf_map__is_pinned(map));
        REQUIRE(calls == 0);
    }
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(bpf_map__unpin(map, pin_path) == 0);
}

TEST_CASE("thread namespace cache retirement restores scope and fails closed", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd held(create_map());
    ebpf_clear_thread_local_storage();
    {
        ioctl_override override;
        device_io_control_handler = [&](auto handle,
                                        auto code,
                                        auto input,
                                        auto input_size,
                                        auto output,
                                        auto output_size,
                                        auto returned,
                                        auto overlapped) {
            if (static_cast<ebpf_operation_header_t*>(input)->id == EBPF_OPERATION_SET_NAMESPACE) {
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            return override.original(handle, code, input, input_size, output, output_size, returned, overlapped);
        };
        uint32_t key = 0, value = 55;
        REQUIRE(bpf_map_update_elem(held.value, &key, &value, 0) == 0);
        REQUIRE(bpf_map_create(BPF_MAP_TYPE_ARRAY, "no_fallback", 4, 4, 1, nullptr) < 0);
    }
    REQUIRE(selected_namespace() == namespace_a);
    namespace_fd restored(create_map());
    REQUIRE(ebpf_set_thread_namespace(&default_namespace) == EBPF_SUCCESS);
    REQUIRE(bpf_map_get_fd_by_id(map_id(restored.value)) < 0);
}

TEST_CASE("thread namespace malformed GET preserves output and explicit SET recovers", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    {
        ioctl_override override;
        device_io_control_handler = [&](auto handle,
                                        auto code,
                                        auto input,
                                        auto input_size,
                                        auto output,
                                        auto output_size,
                                        auto returned,
                                        auto overlapped) {
            auto id = static_cast<ebpf_operation_header_t*>(input)->id;
            auto status = override.original(handle, code, input, input_size, output, output_size, returned, overlapped);
            if (status && id == EBPF_OPERATION_GET_NAMESPACE) {
                static_cast<ebpf_operation_get_namespace_reply_t*>(output)->namespace_id = namespace_b;
            }
            return status;
        };
        GUID output = namespace_b;
        REQUIRE(ebpf_get_thread_namespace(&output) != EBPF_SUCCESS);
        REQUIRE(output == namespace_b);
    }
    REQUIRE(bpf_map_create(BPF_MAP_TYPE_ARRAY, "poisoned", 4, 4, 1, nullptr) < 0);
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE("thread namespace guarded operation retains retired transport", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    {
        ebpf_api_namespace_guard guard;
        namespace_fd first(create_map());
        auto handle = get_sync_device_handle();
        clean_up_sync_device_handle();
        REQUIRE(get_sync_device_handle() == handle);
        REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_INVALID_STATE);
        namespace_fd second(create_map());
        REQUIRE(selected_namespace() == namespace_a);
    }
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE(
    "thread namespace SET and sync retirement leave shared async transport unchanged", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    auto async = get_async_device_handle();
    REQUIRE(async != ebpf_handle_invalid);
    for (const GUID& guid : {namespace_a, namespace_b, default_namespace}) {
        REQUIRE(ebpf_set_thread_namespace(&guid) == EBPF_SUCCESS);
        ebpf_clear_thread_local_storage();
        REQUIRE(get_async_device_handle() == async);
        REQUIRE(selected_namespace() == guid);
    }
}

TEST_CASE("thread namespace insertion receipts survive same-object ABA", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd map(create_map());
    namespace_fd other(create_map());
    bool same_object = GENERATE(true, false);
    int replacement_fd = same_object ? map.value : other.value;
    uint64_t original = 0, replacement = 0;
    REQUIRE(ebpf_object_pin_with_cookie(map.value, pin_path, &original) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin(pin_path) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_pin_with_cookie(replacement_fd, pin_path, &replacement) == EBPF_SUCCESS);
    REQUIRE(original != replacement);
    REQUIRE(ebpf_set_thread_namespace(&namespace_b) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin_if_matches(map.value, pin_path, original) == EBPF_KEY_NOT_FOUND);
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd still_pinned(bpf_obj_get(pin_path));
    REQUIRE(still_pinned.value > 0);
    REQUIRE(map_id(still_pinned.value) == map_id(replacement_fd));
    REQUIRE(ebpf_object_unpin_if_matches(replacement_fd, pin_path, replacement) == EBPF_SUCCESS);
}

TEST_CASE(
    "thread namespace native client failure preserves reused pins and removes owned pins",
    "[namespace][thread_namespace][native]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    bpf_object_open_opts options{};
    options.pin_root_path = "/thread_ns_client_rollback";
    namespace_object object(bpf_object__open_file("map_reuse_um.dll", &options), bpf_object__close);
    REQUIRE(object != nullptr);
    bpf_map* reused = nullptr;
    std::vector<std::string> paths;
    for (auto* map : object->maps) {
        if (map->map_definition.pinning == LIBBPF_PIN_BY_NAME) {
            paths.emplace_back(map->pin_path);
            if (map->map_definition.type == BPF_MAP_TYPE_ARRAY || map->map_definition.type == BPF_MAP_TYPE_HASH) {
                reused = map;
            }
        }
    }
    REQUIRE(reused != nullptr);
    const std::string reused_path = reused->pin_path;
    const auto& definition = reused->map_definition;
    namespace_fd existing(bpf_map_create(
        definition.type, "reuse_control", definition.key_size, definition.value_size, definition.max_entries, nullptr));
    REQUIRE(existing.value > 0);
    REQUIRE(bpf_obj_pin(existing.value, reused_path.c_str()) == 0);
    bool kernel_loaded = false, injected = false;
    {
        ioctl_override override;
        device_io_control_handler = [&](auto handle,
                                        auto code,
                                        auto input,
                                        auto input_size,
                                        auto output,
                                        auto output_size,
                                        auto returned,
                                        auto overlapped) {
            auto id = static_cast<ebpf_operation_header_t*>(input)->id;
            if (kernel_loaded && id == EBPF_OPERATION_GET_OBJECT_INFO) {
                injected = true;
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return FALSE;
            }
            auto result = override.original(handle, code, input, input_size, output, output_size, returned, overlapped);
            if (id == EBPF_OPERATION_LOAD_NATIVE_PROGRAMS_EX && result) {
                kernel_loaded = true;
            }
            return result;
        };
        REQUIRE(bpf_object__load(object.get()) < 0);
    }
    REQUIRE(kernel_loaded);
    REQUIRE(injected);
    for (const auto& path : paths) {
        namespace_fd opened(bpf_obj_get(path.c_str()));
        if (path == reused_path) {
            REQUIRE(opened.value > 0);
            REQUIRE(map_id(opened.value) == map_id(existing.value));
        } else {
            REQUIRE(opened.value < 0);
        }
    }
    REQUIRE(ebpf_object_unpin(reused_path.c_str()) == EBPF_SUCCESS);
}

TEST_CASE("thread namespace file state snapshots closing and overflow", "[namespace][thread_namespace]")
{
    ebpf_namespace_state_t state;
    ebpf_namespace_state_initialize(&state);
    struct cleanup
    {
        ebpf_namespace_state_t* state;
        ~cleanup() { ebpf_namespace_state_destroy(state); }
    } destroy{&state};
    ebpf_request_context_t captured{};
    REQUIRE(ebpf_namespace_state_set(&state, &namespace_a) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_state_capture(&state, &captured) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_state_set(&state, &namespace_b) == EBPF_SUCCESS);
    REQUIRE(captured.namespace_id == namespace_a);
    state.generation = UINT64_MAX;
    REQUIRE(ebpf_namespace_state_set(&state, &namespace_b) == EBPF_SUCCESS);
    REQUIRE(ebpf_namespace_state_set(&state, &namespace_a) == EBPF_ARITHMETIC_OVERFLOW);
    REQUIRE(state.namespace_id == namespace_b);
    ebpf_namespace_state_close(&state);
    REQUIRE(ebpf_namespace_state_capture(&state, &captured) == EBPF_INVALID_STATE);
    REQUIRE(captured.namespace_id == namespace_a);
    REQUIRE(ebpf_namespace_state_set(&state, &namespace_a) == EBPF_INVALID_STATE);
}

TEST_CASE("thread namespace malformed protocol requests preserve file selection", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    ebpf_namespace_state_t state;
    ebpf_namespace_state_initialize(&state);
    struct state_cleanup
    {
        ebpf_namespace_state_t* state;
        ~state_cleanup() { ebpf_namespace_state_destroy(state); }
    } cleanup{&state};
    REQUIRE(ebpf_namespace_state_set(&state, &namespace_b) == EBPF_SUCCESS);
    ebpf_request_context_t scope{};
    REQUIRE(ebpf_namespace_state_capture(&state, &scope) == EBPF_SUCCESS);
    ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, namespace_a};
    for (uint16_t size = 0; size < sizeof(request); ++size) {
        REQUIRE(
            ebpf_core_invoke_protocol_handler(
                &scope, EBPF_OPERATION_SET_NAMESPACE, &request, size, nullptr, 0, nullptr, nullptr) ==
            EBPF_INVALID_ARGUMENT);
        ebpf_request_context_t after{};
        REQUIRE(ebpf_namespace_state_capture(&state, &after) == EBPF_SUCCESS);
        REQUIRE(after.namespace_id == namespace_b);
    }
    scope.namespace_target = nullptr;
    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            &scope, EBPF_OPERATION_SET_NAMESPACE, &request, sizeof(request), nullptr, 0, nullptr, nullptr) ==
        EBPF_INVALID_STATE);
    alignas(ebpf_operation_get_namespace_reply_t) std::array<uint8_t, sizeof(ebpf_operation_get_namespace_reply_t)>
        shared{};
    auto* get = reinterpret_cast<ebpf_operation_get_namespace_request_t*>(shared.data());
    get->header = {sizeof(*get), EBPF_OPERATION_GET_NAMESPACE};
    REQUIRE(
        ebpf_core_invoke_protocol_handler(
            &scope,
            EBPF_OPERATION_GET_NAMESPACE,
            shared.data(),
            sizeof(*get),
            shared.data(),
            static_cast<uint16_t>(shared.size()),
            nullptr,
            nullptr) == EBPF_SUCCESS);
    const auto* reply = reinterpret_cast<const ebpf_operation_get_namespace_reply_t*>(shared.data());
    REQUIRE(reply->header.length == sizeof(*reply));
    REQUIRE(reply->namespace_id == namespace_b);
}

TEST_CASE("thread namespace netsh argument overrides restore selection", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    std::array<std::wstring, 2> text{L"show", L"namespace={2d0fcaf1-5ca8-4329-b74c-accbe7a2aa02}"};
    std::array<LPWSTR, 2> args{text[0].data(), text[1].data()};
    auto command = +[](LPCWSTR, LPWSTR*, DWORD index, DWORD argc, DWORD, LPCVOID, BOOL*) -> unsigned long {
        CHECK(index == 1);
        CHECK(argc == 1);
        CHECK(selected_namespace() == namespace_b);
        return ERROR_INVALID_PARAMETER;
    };
    BOOL done = FALSE;
    REQUIRE(
        ebpf_netsh_namespace_command(command, nullptr, args.data(), 1, 2, 0, nullptr, &done) ==
        ERROR_INVALID_PARAMETER);
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE(
    "thread namespace netsh invalid arguments skip command and restoration errors are reported",
    "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    std::wstring invalid = L"namespace=invalid";
    LPWSTR argument = invalid.data();
    BOOL done = FALSE;
    bool called = false;
    auto command = +[](LPCWSTR, LPWSTR*, DWORD, DWORD, DWORD, LPCVOID data, BOOL*) -> unsigned long {
        *static_cast<bool*>(const_cast<void*>(data)) = true;
        return NO_ERROR;
    };
    REQUIRE(
        ebpf_netsh_namespace_command(command, nullptr, &argument, 0, 1, 0, &called, &done) == ERROR_SUPPRESS_OUTPUT);
    REQUIRE_FALSE(called);
    REQUIRE(selected_namespace() == namespace_a);
    std::wstring valid = L"namespace={2d0fcaf1-5ca8-4329-b74c-accbe7a2aa02}";
    argument = valid.data();
    {
        ioctl_override override;
        device_io_control_handler = [&](auto handle,
                                        auto code,
                                        auto input,
                                        auto input_size,
                                        auto output,
                                        auto output_size,
                                        auto returned,
                                        auto overlapped) {
            auto* header = static_cast<ebpf_operation_header_t*>(input);
            if (header->id == EBPF_OPERATION_SET_NAMESPACE &&
                static_cast<ebpf_operation_set_namespace_request_t*>(input)->namespace_id == namespace_a) {
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            return override.original(handle, code, input, input_size, output, output_size, returned, overlapped);
        };
        REQUIRE(
            ebpf_netsh_namespace_command(command, nullptr, &argument, 0, 1, 0, &called, &done) ==
            ERROR_SUPPRESS_OUTPUT);
    }
    REQUIRE(called);
    REQUIRE(selected_namespace() == namespace_b);
}

TEST_CASE(
    "thread namespace netsh omitted argument does not change or reauthorize selection", "[namespace][thread_namespace]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    unsigned long calls = 0;
    ioctl_override override;
    device_io_control_handler = [&](auto handle,
                                    auto code,
                                    auto input,
                                    auto input_size,
                                    auto output,
                                    auto output_size,
                                    auto returned,
                                    auto overlapped) {
        auto id = static_cast<ebpf_operation_header_t*>(input)->id;
        if (id == EBPF_OPERATION_GET_NAMESPACE || id == EBPF_OPERATION_SET_NAMESPACE) {
            ++calls;
        }
        return override.original(handle, code, input, input_size, output, output_size, returned, overlapped);
    };
    auto command = +[](LPCWSTR, LPWSTR*, DWORD, DWORD, DWORD, LPCVOID, BOOL*) -> unsigned long { return NO_ERROR; };
    BOOL done = FALSE;
    REQUIRE(ebpf_netsh_namespace_command(command, nullptr, nullptr, 0, 0, 0, nullptr, &done) == NO_ERROR);
    REQUIRE(calls == 0);
    REQUIRE(selected_namespace() == namespace_a);
}
#endif

#if !defined(EBPF_NAMESPACE_UNIT_TEST)
TEST_CASE(
    "thread namespace driver complete DLL reload resets surviving threads", "[namespace][thread_namespace][driver]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_fd map(create_map());
    REQUIRE(bpf_obj_pin(map.value, pin_path) == 0);
    std::array<wchar_t, 32768> module_path{};
    DWORD length = GetModuleFileNameW(nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
    REQUIRE(length > 0);
    REQUIRE(length < module_path.size());
    auto directory = std::filesystem::path(module_path.data()).parent_path();
    auto script = directory / "thread_namespace_dll_lifetime.ps1";
    auto sdk = directory / "ebpfapi.dll";
    std::wstring command = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                           script.wstring() + L"\" -SdkDll \"" + sdk.wstring() +
                           L"\" -PinPath \"BPF:\\thread_namespace_regression\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    BOOL started = CreateProcessW(
        nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, directory.c_str(), &startup, &process);
    REQUIRE(started);
    DWORD wait = WaitForSingleObject(process.hProcess, 60000);
    if (wait != WAIT_OBJECT_0) {
        CHECK(TerminateProcess(process.hProcess, 1));
        CHECK(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0);
    }
    DWORD exit_code = 1;
    BOOL queried = GetExitCodeProcess(process.hProcess, &exit_code);
    CHECK(CloseHandle(process.hThread));
    CHECK(CloseHandle(process.hProcess));
    CHECK(ebpf_object_unpin(pin_path) == EBPF_SUCCESS);
    REQUIRE(wait == WAIT_OBJECT_0);
    REQUIRE(queried);
    REQUIRE(exit_code == 0);
}

TEST_CASE(
    "thread namespace driver authorization checks effective impersonation", "[namespace][thread_namespace][driver]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    HANDLE token = nullptr, restricted = nullptr;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &token));
    BYTE sid[SECURITY_MAX_SID_SIZE]{};
    DWORD sid_size = sizeof(sid);
    REQUIRE(CreateWellKnownSid(WinWorldSid, nullptr, sid, &sid_size));
    SID_AND_ATTRIBUTES restrict_sid{sid, 0};
    BOOL created =
        CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 1, &restrict_sid, &restricted);
    REQUIRE(CloseHandle(token));
    REQUIRE(created);
    BOOL impersonated = ImpersonateLoggedOnUser(restricted);
    REQUIRE(CloseHandle(restricted));
    REQUIRE(impersonated);
    struct revert_scope
    {
        ~revert_scope() { CHECK(RevertToSelf()); }
    };
    ebpf_result_t same, reset, get;
    GUID output = namespace_b;
    {
        revert_scope revert;
        same = ebpf_set_thread_namespace(&namespace_a);
        reset = ebpf_set_thread_namespace(&default_namespace);
        get = ebpf_get_thread_namespace(&output);
    }
    REQUIRE(same == EBPF_ACCESS_DENIED);
    REQUIRE(reset == EBPF_ACCESS_DENIED);
    REQUIRE(get == EBPF_ACCESS_DENIED);
    REQUIRE(output == namespace_b);
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE(
    "thread namespace driver rejects namespace control on bound object files", "[namespace][thread_namespace][driver]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_control_file control;
    control.select(namespace_a);
    auto handle = control.create_map_handle({BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1});
    std::unique_ptr<void, decltype(&CloseHandle)> object(reinterpret_cast<HANDLE>(handle), CloseHandle);
    ebpf_operation_set_namespace_request_t request{{sizeof(request), EBPF_OPERATION_SET_NAMESPACE}, namespace_b};
    DWORD returned = 0;
    constexpr DWORD ioctl = CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
    REQUIRE_FALSE(DeviceIoControl(object.get(), ioctl, &request, sizeof(request), nullptr, 0, &returned, nullptr));
    REQUIRE(selected_namespace() == namespace_a);
    REQUIRE(control.query_map_id(handle) != 0);
}

TEST_CASE(
    "thread namespace driver queued queries retain objects through handle closure",
    "[namespace][thread_namespace][driver]")
{
    namespace_fixture fixture;
    REQUIRE(ebpf_set_thread_namespace(&namespace_a) == EBPF_SUCCESS);
    namespace_control_file creator;
    creator.select(namespace_a);
    auto map = creator.create_map_handle({BPF_MAP_TYPE_RINGBUF, 0, 0, 65536});
    uint32_t id = creator.query_map_id(map);
    HANDLE file = CreateFileW(
        EBPF_DEVICE_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, nullptr);
    REQUIRE(file != INVALID_HANDLE_VALUE);
    OVERLAPPED overlapped{};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    REQUIRE(overlapped.hEvent != nullptr);
    ebpf_operation_map_async_query_request_t request{};
    request.header = {sizeof(request), EBPF_OPERATION_MAP_ASYNC_QUERY};
    request.map_handle = map;
    ebpf_operation_map_async_query_reply_t reply{};
    constexpr DWORD ioctl = CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
    DWORD returned = 0;
    BOOL completed =
        DeviceIoControl(file, ioctl, &request, sizeof(request), &reply, sizeof(reply), &returned, &overlapped);
    DWORD error = completed ? ERROR_SUCCESS : GetLastError();
    CHECK((completed || error == ERROR_IO_PENDING));
    CHECK(CloseHandle(reinterpret_cast<HANDLE>(map)));
    CHECK(CloseHandle(file));
    DWORD wait = WaitForSingleObject(overlapped.hEvent, 10000);
    CHECK(CloseHandle(overlapped.hEvent));
    REQUIRE(wait == WAIT_OBJECT_0);
    bool removed = false;
    for (size_t attempt = 0; attempt < 1000; ++attempt) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) {
            removed = true;
            break;
        }
        REQUIRE(ebpf_close_fd(fd) == EBPF_SUCCESS);
        Sleep(1);
    }
    REQUIRE(removed);
    REQUIRE(selected_namespace() == namespace_a);
}

TEST_CASE(
    "thread namespace driver file cleanup drains pending epoch requests independently",
    "[namespace][thread_namespace][driver]")
{
    namespace_fixture fixture;
    namespace_control_file survivor;
    survivor.select(namespace_b);
    constexpr DWORD ioctl = CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS);
    for (size_t iteration = 0; iteration < 100; ++iteration) {
        HANDLE file = CreateFileW(
            EBPF_DEVICE_WIN32_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_FLAG_OVERLAPPED,
            nullptr);
        REQUIRE(file != INVALID_HANDLE_VALUE);
        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        REQUIRE(overlapped.hEvent != nullptr);
        ebpf_operation_epoch_synchronize_request_t request{{sizeof(request), EBPF_OPERATION_EPOCH_SYNCHRONIZE}};
        DWORD returned = 0;
        BOOL completed = DeviceIoControl(file, ioctl, &request, sizeof(request), nullptr, 0, &returned, &overlapped);
        DWORD error = completed ? ERROR_SUCCESS : GetLastError();
        REQUIRE((completed || error == ERROR_IO_PENDING));
        REQUIRE(CloseHandle(file));
        REQUIRE(WaitForSingleObject(overlapped.hEvent, 10000) == WAIT_OBJECT_0);
        REQUIRE(CloseHandle(overlapped.hEvent));
        REQUIRE(survivor.get() == namespace_b);
    }
}
#endif
