// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_fault_injection.h"
#include "ebpf_leak_detector.h"
#include "ebpf_symbol_decoder.h"
#include "ebpf_utilities.h"

#include <TraceLoggingProvider.h>
#include <functional>
#include <intsafe.h>
#include <map>
#include <mutex>
#include <queue>
#include <random>
#include <set>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <vector>

// Global variables used to override behavior for testing.
// Permit the test to simulate both Hyper-V Code Integrity.
bool _ebpf_platform_code_integrity_enabled = false;
// Permit the test to simulate non-preemptible execution.
bool _ebpf_platform_is_preemptible = true;

// Global variable to track the number of times ebpf_platform has been
// initialized. In user mode it is possible for ebpf_platform_{initiate|terminate}
// to be called multiple times.
int32_t _ebpf_platform_initiate_count = 0;

extern "C" bool ebpf_fuzzing_enabled = false;
extern "C" size_t ebpf_fuzzing_memory_limit = MAXSIZE_T;

ebpf_leak_detector_ptr _ebpf_leak_detector_ptr;

/**
 * @brief Environment variable to enable fault injection testing.
 *
 */
#define EBPF_FAULT_INJECTION_SIMULATION_ENVIRONMENT_VARIABLE_NAME "EBPF_FAULT_INJECTION_SIMULATION"
#define EBPF_MEMORY_LEAK_DETECTION_ENVIRONMENT_VARIABLE_NAME "EBPF_MEMORY_LEAK_DETECTION"

// Thread pool related globals.
static TP_CALLBACK_ENVIRON _callback_environment{};
static PTP_POOL _pool = nullptr;
static PTP_CLEANUP_GROUP _cleanup_group = nullptr;

static uint32_t _ebpf_platform_maximum_group_count = 0;
static uint32_t _ebpf_platform_maximum_processor_count = 0;

// The starting index of the first processor in each group.
// Used to compute the current CPU index.
static std::vector<uint32_t> _ebpf_platform_group_to_index_map;

static ebpf_result_t
_initialize_thread_pool()
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool cleanup_group_created = false;
    bool return_value;

    // Initialize a callback environment for the thread pool.
    InitializeThreadpoolEnvironment(&_callback_environment);

    // CreateThreadpoolCleanupGroup can return nullptr.
    if (ebpf_fault_injection_inject_fault()) {
        return EBPF_NO_MEMORY;
    }

    _pool = CreateThreadpool(nullptr);
    if (_pool == nullptr) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }

    SetThreadpoolThreadMaximum(_pool, 1);
    return_value = SetThreadpoolThreadMinimum(_pool, 1);
    if (!return_value) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }

    _cleanup_group = CreateThreadpoolCleanupGroup();
    if (_cleanup_group == nullptr) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }
    cleanup_group_created = true;

    SetThreadpoolCallbackPool(&_callback_environment, _pool);
    SetThreadpoolCallbackCleanupGroup(&_callback_environment, _cleanup_group, nullptr);

Exit:
    if (result != EBPF_SUCCESS) {
        if (cleanup_group_created) {
            CloseThreadpoolCleanupGroup(_cleanup_group);
        }
        if (_pool) {
            CloseThreadpool(_pool);
            _pool = nullptr;
        }
    }
    return result;
}

static void
_clean_up_thread_pool()
{
    if (!_pool) {
        return;
    }

    if (_cleanup_group) {
        CloseThreadpoolCleanupGroupMembers(_cleanup_group, false, nullptr);
        CloseThreadpoolCleanupGroup(_cleanup_group);
        _cleanup_group = nullptr;
    }
    CloseThreadpool(_pool);
    _pool = nullptr;
}

class _ebpf_emulated_dpc;

thread_local bool ebpf_non_preemptible = false;

typedef struct _ebpf_non_preemptible_work_item
{
    ebpf_list_entry_t entry;
    void* context;
    _ebpf_emulated_dpc* queue;
    void* parameter_1;
    void (*work_item_routine)(_Inout_opt_ void* work_item_context, _Inout_opt_ void* parameter_1);
} ebpf_non_preemptible_work_item_t;

class _ebpf_emulated_dpc;
static std::vector<std::shared_ptr<_ebpf_emulated_dpc>> _ebpf_emulated_dpcs;

/**
 * @brief This class emulates kernel mode DPCs by maintaining a per-CPU thread running at maximum priority.
 * Work items can be queued to this thread, which then executes them without being interrupted by lower
 * priority threads.
 */
class _ebpf_emulated_dpc
{
  public:
    _ebpf_emulated_dpc() = delete;

    /**
     * @brief Construct a new ebpf emulated dpc object for CPU i.
     *
     * @param[in] i CPU to run on.
     */
    _ebpf_emulated_dpc(size_t i) : head({}), terminate(false)
    {
        ebpf_list_initialize(&head);
        thread = std::thread([i, this]() {
            ebpf_non_preemptible = true;
            std::unique_lock<std::mutex> l(mutex);
            uintptr_t old_thread_affinity;
            ebpf_assert_success(ebpf_set_current_thread_affinity(1ull << i, &old_thread_affinity));
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
            for (;;) {
                if (terminate) {
                    return;
                }
                if (!ebpf_list_is_empty(&head)) {
                    auto entry = ebpf_list_remove_head_entry(&head);
                    if (entry == &flush_entry) {
                        ebpf_list_initialize(&flush_entry);
                        condition_variable.notify_all();
                    } else {
                        l.unlock();
                        ebpf_list_initialize(entry);
                        auto work_item = reinterpret_cast<ebpf_non_preemptible_work_item_t*>(entry);
                        work_item->work_item_routine(work_item->context, work_item->parameter_1);
                        l.lock();
                    }
                }
                condition_variable.wait(l, [this]() { return terminate || !ebpf_list_is_empty(&head); });
            }
        });
    }

    /**
     * @brief Destroy the ebpf emulated dpc object.
     *
     */
    ~_ebpf_emulated_dpc()
    {
        terminate = true;
        condition_variable.notify_all();
        thread.join();
    }

    /**
     * @brief Wait for all currently queued work items to complete.
     *
     */
    void
    flush_queue()
    {
        std::unique_lock<std::mutex> l(mutex);
        // Insert a marker in the queue.
        ebpf_list_initialize(&flush_entry);
        ebpf_list_insert_tail(&head, &flush_entry);
        condition_variable.notify_all();
        // Wait until the marker is processed.
        condition_variable.wait(l, [this]() { return terminate || ebpf_list_is_empty(&flush_entry); });
    }

    /**
     * @brief Insert a work item into its associated queue.
     *
     * @param[in, out] work_item Work item to be enqueued.
     * @param[in] parameter_1 Parameter to pass to worker function.
     * @retval true Work item wasn't already queued.
     * @retval false Work item is already queued.
     */
    static bool
    insert(_Inout_ ebpf_non_preemptible_work_item_t* work_item, _Inout_opt_ void* parameter_1)
    {
        auto& dpc_queue = *(work_item->queue);
        std::unique_lock<std::mutex> l(dpc_queue.mutex);
        if (!ebpf_list_is_empty(&work_item->entry)) {
            return false;
        } else {
            work_item->parameter_1 = parameter_1;
            ebpf_list_insert_tail(&dpc_queue.head, &work_item->entry);
            dpc_queue.condition_variable.notify_all();
            return true;
        }
    }

  private:
    ebpf_list_entry_t flush_entry;
    ebpf_list_entry_t head;
    std::thread thread;
    std::mutex mutex;
    std::condition_variable condition_variable;
    bool terminate;
};

/**
 * @brief Get an environment variable as a string.
 *
 * @param[in] name Environment variable name.
 * @return String value of environment variable or an empty string if not set.
 */
static std::string
_get_environment_variable_as_string(const std::string& name)
{
    std::string value;
    size_t required_size = 0;
    getenv_s(&required_size, nullptr, 0, name.c_str());
    if (required_size > 0) {
        value.resize(required_size);
        getenv_s(&required_size, &value[0], required_size, name.c_str());
        value.resize(required_size - 1);
    }
    return value;
}

/**
 * @brief Get an environment variable as a boolean.
 *
 * @param[in] name Environment variable name.
 * @retval false Environment variable is set to "false", "0", or if it's not set.
 * @retval true Environment variable is set to any other value.
 */
static bool
_get_environment_variable_as_bool(const std::string& name)
{
    std::string value = _get_environment_variable_as_string(name);
    if (value.empty()) {
        return false;
    }

    // Convert value to lower case.
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    if (value == "false") {
        return false;
    }
    if (value == "0") {
        return false;
    }
    return true;
}

/**
 * @brief Get an environment variable as a size_t.
 *
 * @param[in] name Environment variable name.
 * @return Value of environment variable or 0 if it's not set or not a valid number.
 */
static size_t
_get_environment_variable_as_size_t(const std::string& name)
{
    std::string value = _get_environment_variable_as_string(name);
    if (value.empty()) {
        return 0;
    }
    try {
        return std::stoull(value);
    } catch (const std::exception&) {
        return 0;
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_platform_initiate()
{
    int32_t count = ebpf_interlocked_increment_int32(&_ebpf_platform_initiate_count);
    if (count > 1) {
        // Platform library already initialized, return.
        return EBPF_SUCCESS;
    }

    try {
        _ebpf_platform_maximum_group_count = GetMaximumProcessorGroupCount();
        _ebpf_platform_maximum_processor_count = GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS);
        auto fault_injection_stack_depth =
            _get_environment_variable_as_size_t(EBPF_FAULT_INJECTION_SIMULATION_ENVIRONMENT_VARIABLE_NAME);
        auto leak_detector = _get_environment_variable_as_bool(EBPF_MEMORY_LEAK_DETECTION_ENVIRONMENT_VARIABLE_NAME);
        if (fault_injection_stack_depth || leak_detector) {
            _ebpf_symbol_decoder_initialize();
        }
        if (fault_injection_stack_depth && !ebpf_fault_injection_is_enabled()) {
            if (ebpf_fault_injection_initialize(fault_injection_stack_depth) != EBPF_SUCCESS) {
                return EBPF_NO_MEMORY;
            }
            // Set flag to remove some asserts that fire from incorrect client behavior.
            ebpf_fuzzing_enabled = true;
        }

        if (leak_detector) {
            _ebpf_leak_detector_ptr = std::make_unique<ebpf_leak_detector_t>();
        }

        for (size_t i = 0; i < ebpf_get_cpu_count(); i++) {
            _ebpf_emulated_dpcs.push_back(std::make_shared<_ebpf_emulated_dpc>(i));
        }
        // Compute the starting index of each processor group.
        _ebpf_platform_group_to_index_map.resize(_ebpf_platform_maximum_group_count);
        uint32_t base_index = 0;
        for (size_t i = 0; i < _ebpf_platform_group_to_index_map.size(); i++) {
            _ebpf_platform_group_to_index_map[i] = base_index;
            base_index += GetMaximumProcessorCount((uint16_t)i);
        }
    } catch (const std::bad_alloc&) {
        return EBPF_NO_MEMORY;
    }

    return _initialize_thread_pool();
}

void
ebpf_platform_terminate()
{
    int32_t count = ebpf_interlocked_decrement_int32(&_ebpf_platform_initiate_count);
    if (count != 0) {
        return;
    }

    _clean_up_thread_pool();
    _ebpf_emulated_dpcs.resize(0);
    if (_ebpf_leak_detector_ptr) {
        _ebpf_leak_detector_ptr->dump_leaks();
        _ebpf_leak_detector_ptr.reset();
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_get_code_integrity_state(_Out_ ebpf_code_integrity_state_t* state)
{
    EBPF_LOG_ENTRY();
    if (_ebpf_platform_code_integrity_enabled) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity enabled");
        *state = EBPF_CODE_INTEGRITY_HYPERVISOR_KERNEL_MODE;
    } else {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_BASE, "Code integrity disabled");
        *state = EBPF_CODE_INTEGRITY_DEFAULT;
    }
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(size) void* ebpf_allocate(size_t size)
{
    ebpf_assert(size);
    if (size > ebpf_fuzzing_memory_limit) {
        return nullptr;
    }

    if (ebpf_fault_injection_inject_fault()) {
        return nullptr;
    }

    void* memory;
    memory = calloc(size, 1);
    if (memory != nullptr) {
        memset(memory, 0, size);
    }

    if (memory && _ebpf_leak_detector_ptr) {
        _ebpf_leak_detector_ptr->register_allocation(reinterpret_cast<uintptr_t>(memory), size);
    }

    return memory;
}

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_with_tag(size_t size, uint32_t tag)
{
    UNREFERENCED_PARAMETER(tag);

    return ebpf_allocate(size);
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate(
    _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size)
{
    UNREFERENCED_PARAMETER(old_size);
    if (new_size > ebpf_fuzzing_memory_limit) {
        return nullptr;
    }

    if (ebpf_fault_injection_inject_fault()) {
        return nullptr;
    }

    void* p = realloc(memory, new_size);
    if (p && (new_size > old_size)) {
        memset(((char*)p) + old_size, 0, new_size - old_size);
    }

    if (_ebpf_leak_detector_ptr) {
        _ebpf_leak_detector_ptr->unregister_allocation(reinterpret_cast<uintptr_t>(memory));
        _ebpf_leak_detector_ptr->register_allocation(reinterpret_cast<uintptr_t>(p), new_size);
    }

    return p;
}

__drv_allocatesMem(Mem) _Must_inspect_result_ _Ret_writes_maybenull_(new_size) void* ebpf_reallocate_with_tag(
    _In_ _Post_invalid_ void* memory, size_t old_size, size_t new_size, uint32_t tag)
{
    UNREFERENCED_PARAMETER(tag);

    return ebpf_reallocate(memory, old_size, new_size);
}

void
ebpf_free(_Frees_ptr_opt_ void* memory)
{
    if (_ebpf_leak_detector_ptr) {
        _ebpf_leak_detector_ptr->unregister_allocation(reinterpret_cast<uintptr_t>(memory));
    }
    free(memory);
}

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned(size_t size)
{
    if (size > ebpf_fuzzing_memory_limit) {
        return nullptr;
    }

    if (ebpf_fault_injection_inject_fault()) {
        return nullptr;
    }

    void* memory = _aligned_malloc(size, EBPF_CACHE_LINE_SIZE);
    if (memory) {
        memset(memory, 0, size);
    }
    return memory;
}

__drv_allocatesMem(Mem) _Must_inspect_result_
    _Ret_writes_maybenull_(size) void* ebpf_allocate_cache_aligned_with_tag(size_t size, uint32_t tag)
{
    UNREFERENCED_PARAMETER(tag);

    return ebpf_allocate_cache_aligned(size);
}

void
ebpf_free_cache_aligned(_Frees_ptr_opt_ void* memory)
{
    _aligned_free(memory);
}

struct _ebpf_memory_descriptor
{
    void* base;
    size_t length;
};
typedef struct _ebpf_memory_descriptor ebpf_memory_descriptor_t;

struct _ebpf_ring_descriptor
{
    void* primary_view;
    void* secondary_view;
    size_t length;
};
typedef struct _ebpf_ring_descriptor ebpf_ring_descriptor_t;

ebpf_memory_descriptor_t*
ebpf_map_memory(size_t length)
{
    // Skip fault injection for this VirtualAlloc OS API, as ebpf_allocate already does that.
    ebpf_memory_descriptor_t* descriptor = (ebpf_memory_descriptor_t*)ebpf_allocate(sizeof(ebpf_memory_descriptor_t));
    if (!descriptor) {
        return nullptr;
    }

    descriptor->base = VirtualAlloc(0, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    descriptor->length = length;

    if (!descriptor->base) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualAlloc);
        ebpf_free(descriptor);
        descriptor = nullptr;
    }
    return descriptor;
}

void
ebpf_unmap_memory(_Frees_ptr_opt_ ebpf_memory_descriptor_t* memory_descriptor)
{
    if (memory_descriptor) {
        if (!VirtualFree(memory_descriptor->base, 0, MEM_RELEASE)) {
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualFree);
        }
        ebpf_free(memory_descriptor);
    }
}

// This code is derived from the sample at:
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2

_Ret_maybenull_ ebpf_ring_descriptor_t*
ebpf_allocate_ring_buffer_memory(size_t length)
{
    EBPF_LOG_ENTRY();
    bool result = false;
    HANDLE section = nullptr;
    SYSTEM_INFO sysInfo;
    uint8_t* placeholder1 = nullptr;
    uint8_t* placeholder2 = nullptr;
    void* view1 = nullptr;
    void* view2 = nullptr;

    // Skip fault injection for this VirtualAlloc2 OS API, as ebpf_allocate already does that.
    GetSystemInfo(&sysInfo);

    if (length == 0) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Ring buffer length is zero");
        return nullptr;
    }

    if ((length % sysInfo.dwAllocationGranularity) != 0) {
        EBPF_LOG_MESSAGE_UINT64(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Ring buffer length doesn't match allocation granularity",
            length);
        return nullptr;
    }

    ebpf_ring_descriptor_t* descriptor = (ebpf_ring_descriptor_t*)ebpf_allocate(sizeof(ebpf_ring_descriptor_t));
    if (!descriptor) {
        goto Exit;
    }
    descriptor->length = length;

    //
    // Reserve a placeholder region where the buffer will be mapped.
    //
    placeholder1 = reinterpret_cast<uint8_t*>(
        VirtualAlloc2(nullptr, nullptr, 2 * length, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0));

    if (placeholder1 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualAlloc2);
        goto Exit;
    }

#pragma warning(push)
#pragma warning(disable : 6333)  // Invalid parameter:  passing MEM_RELEASE and a non-zero dwSize parameter to
                                 // 'VirtualFree' is not allowed.  This causes the call to fail.
#pragma warning(disable : 28160) // Passing MEM_RELEASE and a non-zero dwSize parameter to VirtualFree is not allowed.
                                 // This results in the failure of this call.
    //
    // Split the placeholder region into two regions of equal size.
    //
    result = VirtualFree(placeholder1, length, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    if (result == FALSE) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualFree);
        goto Exit;
    }
#pragma warning(pop)
    placeholder2 = placeholder1 + length;

    //
    // Create a pagefile-backed section for the buffer.
    //

    section = CreateFileMapping(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<unsigned long>(length), nullptr);
    if (section == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, CreateFileMapping);
        goto Exit;
    }

    //
    // Map the section into the first placeholder region.
    //
    view1 =
        MapViewOfFile3(section, nullptr, placeholder1, 0, length, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view1 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile3);
        goto Exit;
    }

    //
    // Ownership transferred, don't free this now.
    //
    placeholder1 = nullptr;

    //
    // Map the section into the second placeholder region.
    //
    view2 =
        MapViewOfFile3(section, nullptr, placeholder2, 0, length, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view2 == nullptr) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, MapViewOfFile3);
        goto Exit;
    }

    result = true;

    //
    // Success, return both mapped views to the caller.
    //
    descriptor->primary_view = view1;
    descriptor->secondary_view = view2;

    placeholder2 = nullptr;
    view1 = nullptr;
    view2 = nullptr;
Exit:
    if (!result) {
        ebpf_free(descriptor);
        descriptor = nullptr;
    }

    if (section != nullptr) {
        CloseHandle(section);
    }

    if (placeholder1 != nullptr) {
        VirtualFree(placeholder1, 0, MEM_RELEASE);
    }

    if (placeholder2 != nullptr) {
        VirtualFree(placeholder2, 0, MEM_RELEASE);
    }

    if (view1 != nullptr) {
        UnmapViewOfFileEx(view1, 0);
    }

    if (view2 != nullptr) {
        UnmapViewOfFileEx(view2, 0);
    }

    EBPF_RETURN_POINTER(ebpf_ring_descriptor_t*, descriptor);
}

void
ebpf_free_ring_buffer_memory(_Frees_ptr_opt_ ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    if (ring) {
        UnmapViewOfFile(ring->primary_view);
        UnmapViewOfFile(ring->secondary_view);
        ebpf_free(ring);
    }
    EBPF_RETURN_VOID();
}

void*
ebpf_ring_descriptor_get_base_address(_In_ const ebpf_ring_descriptor_t* ring_descriptor)
{
    return ring_descriptor->primary_view;
}

_Ret_maybenull_ void*
ebpf_ring_map_readonly_user(_In_ const ebpf_ring_descriptor_t* ring)
{
    EBPF_LOG_ENTRY();
    EBPF_RETURN_POINTER(void*, ebpf_ring_descriptor_get_base_address(ring));
}

_Must_inspect_result_ ebpf_result_t
ebpf_protect_memory(_In_ const ebpf_memory_descriptor_t* memory_descriptor, ebpf_page_protection_t protection)
{
    // VirtualProtect OS API can return nullptr.
    if (ebpf_fault_injection_inject_fault()) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    EBPF_LOG_ENTRY();
    unsigned long mm_protection_state = 0;
    unsigned long old_mm_protection_state = 0;
    switch (protection) {
    case EBPF_PAGE_PROTECT_READ_ONLY:
        mm_protection_state = PAGE_READONLY;
        break;
    case EBPF_PAGE_PROTECT_READ_WRITE:
        mm_protection_state = PAGE_READWRITE;
        break;
    case EBPF_PAGE_PROTECT_READ_EXECUTE:
        mm_protection_state = PAGE_EXECUTE_READ;
        break;
    default:
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    if (!VirtualProtect(
            memory_descriptor->base, memory_descriptor->length, mm_protection_state, &old_mm_protection_state)) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, VirtualProtect);
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

void*
ebpf_memory_descriptor_get_base_address(ebpf_memory_descriptor_t* memory_descriptor)
{
    return memory_descriptor->base;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_multiply(
    size_t multiplicand, size_t multiplier, _Out_ _Deref_out_range_(==, multiplicand* multiplier) size_t* result)
{
    return SUCCEEDED(SizeTMult(multiplicand, multiplier, result)) ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_add(size_t augend, size_t addend, _Out_ _Deref_out_range_(==, augend + addend) size_t* result)
{
    return SUCCEEDED(SizeTAdd(augend, addend, result)) ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

_Must_inspect_result_ ebpf_result_t
ebpf_safe_size_t_subtract(
    size_t minuend, size_t subtrahend, _Out_ _Deref_out_range_(==, minuend - subtrahend) size_t* result)
{
    return SUCCEEDED(SizeTSub(minuend, subtrahend, result)) ? EBPF_SUCCESS : EBPF_ARITHMETIC_OVERFLOW;
}

void
ebpf_lock_create(_Out_ ebpf_lock_t* lock)
{
    InitializeSRWLock(reinterpret_cast<PSRWLOCK>(lock));
}

void
ebpf_lock_destroy(_In_ _Post_invalid_ ebpf_lock_t* lock)
{
    UNREFERENCED_PARAMETER(lock);
}

_Requires_lock_not_held_(*lock) _Acquires_lock_(*lock) _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) ebpf_lock_state_t ebpf_lock_lock(_Inout_ ebpf_lock_t* lock)
{
    AcquireSRWLockExclusive(reinterpret_cast<PSRWLOCK>(lock));
    return 0;
}

_Requires_lock_held_(*lock) _Releases_lock_(*lock) _IRQL_requires_(DISPATCH_LEVEL) void ebpf_lock_unlock(
    _Inout_ ebpf_lock_t* lock, _IRQL_restores_ ebpf_lock_state_t state)
{
    UNREFERENCED_PARAMETER(state);
    ReleaseSRWLockExclusive(reinterpret_cast<PSRWLOCK>(lock));
}

uint32_t
ebpf_random_uint32()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    return mt();
}

uint64_t
ebpf_query_time_since_boot(bool include_suspended_time)
{
    uint64_t interrupt_time;
    if (include_suspended_time) {
        // QueryUnbiasedInterruptTimePrecise returns A pointer to a ULONGLONG in which to receive the interrupt-time
        // count in system time units of 100 nanoseconds.
        // Unbiased Interrupt time is the total time since boot including time spent suspended.
        // https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttimeprecise.
        QueryUnbiasedInterruptTimePrecise(&interrupt_time);
    } else {
        // QueryInterruptTimePrecise returns A pointer to a ULONGLONG in which to receive the interrupt-time count in
        // system time units of 100 nanoseconds.
        // (Biased) Interrupt time is the total time since boot excluding time spent suspended.
        // https://docs.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise.
        QueryInterruptTimePrecise(&interrupt_time);
    }

    return interrupt_time;
}

_Must_inspect_result_ ebpf_result_t
ebpf_set_current_thread_affinity(uintptr_t new_thread_affinity_mask, _Out_ uintptr_t* old_thread_affinity_mask)
{
    uintptr_t old_mask = SetThreadAffinityMask(GetCurrentThread(), new_thread_affinity_mask);
    if (old_mask == 0) {
        unsigned long error = GetLastError();
        ebpf_assert(error != ERROR_SUCCESS);
        return EBPF_OPERATION_NOT_SUPPORTED;
    } else {
        *old_thread_affinity_mask = old_mask;
        return EBPF_SUCCESS;
    }
}

void
ebpf_restore_current_thread_affinity(uintptr_t old_thread_affinity_mask)
{
    SetThreadAffinityMask(GetCurrentThread(), old_thread_affinity_mask);
}

_Ret_range_(>, 0) uint32_t ebpf_get_cpu_count() { return _ebpf_platform_maximum_processor_count; }

bool
ebpf_is_preemptible()
{
    return !ebpf_non_preemptible;
}

bool
ebpf_is_non_preemptible_work_item_supported()
{
    return true;
}

uint32_t
ebpf_get_current_cpu()
{
    PROCESSOR_NUMBER processor_number;
    GetCurrentProcessorNumberEx(&processor_number);
    // Compute the CPU index from the group and number.
    return _ebpf_platform_group_to_index_map[processor_number.Group] + processor_number.Number;
}

uint64_t
ebpf_get_current_thread_id()
{
    return GetCurrentThreadId();
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_non_preemptible_work_item(
    _Outptr_ ebpf_non_preemptible_work_item_t** work_item,
    uint32_t cpu_id,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context, _Inout_opt_ void* parameter_1),
    _Inout_opt_ void* work_item_context)
{
    auto local_work_item =
        reinterpret_cast<ebpf_non_preemptible_work_item_t*>(ebpf_allocate(sizeof(ebpf_non_preemptible_work_item_t)));
    if (!local_work_item) {
        return EBPF_NO_MEMORY;
    }
    ebpf_list_initialize(&local_work_item->entry);
    local_work_item->queue = _ebpf_emulated_dpcs[cpu_id].get();
    local_work_item->work_item_routine = work_item_routine;
    local_work_item->context = work_item_context;
    *work_item = local_work_item;
    local_work_item = nullptr;
    return EBPF_SUCCESS;
}

void
ebpf_free_non_preemptible_work_item(_Frees_ptr_opt_ ebpf_non_preemptible_work_item_t* work_item)
{
    ebpf_free(work_item);
}

bool
ebpf_queue_non_preemptible_work_item(_Inout_ ebpf_non_preemptible_work_item_t* work_item, _Inout_opt_ void* parameter_1)
{
    return _ebpf_emulated_dpc::insert(work_item, parameter_1);
}

typedef struct _ebpf_preemptible_work_item
{
    PTP_WORK work;
    void (*work_item_routine)(_Inout_opt_ void* work_item_context);
    void* work_item_context;
} ebpf_preemptible_work_item_t;

static void
_ebpf_preemptible_routine(_Inout_ PTP_CALLBACK_INSTANCE instance, _In_opt_ void* parameter, _Inout_ PTP_WORK work)
{
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(work);

    if (parameter == nullptr) {
        return;
    }

    ebpf_preemptible_work_item_t* work_item = (ebpf_preemptible_work_item_t*)parameter;
    work_item->work_item_routine(work_item->work_item_context);

    ebpf_free_preemptible_work_item(work_item);
}

void
ebpf_free_preemptible_work_item(_Frees_ptr_opt_ ebpf_preemptible_work_item_t* work_item)
{
    if (!work_item) {
        return;
    }

    CloseThreadpoolWork(work_item->work);
    ebpf_free(work_item->work_item_context);
    ebpf_free(work_item);
}

void
ebpf_queue_preemptible_work_item(_Inout_ ebpf_preemptible_work_item_t* work_item)
{
    SubmitThreadpoolWork(work_item->work);
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_preemptible_work_item(
    _Outptr_ ebpf_preemptible_work_item_t** work_item,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
    _Inout_opt_ void* work_item_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    *work_item = (ebpf_preemptible_work_item_t*)ebpf_allocate(sizeof(ebpf_preemptible_work_item_t));
    if (*work_item == nullptr) {
        return EBPF_NO_MEMORY;
    }

    // It is required to use the InitializeThreadpoolEnvironment function to
    // initialize the _callback_environment structure before calling CreateThreadpoolWork.
    (*work_item)->work = CreateThreadpoolWork(_ebpf_preemptible_routine, *work_item, &_callback_environment);
    if ((*work_item)->work == nullptr) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        goto Done;
    }
    (*work_item)->work_item_routine = work_item_routine;
    (*work_item)->work_item_context = work_item_context;

Done:
    if (result != EBPF_SUCCESS) {
        ebpf_free(*work_item);
        *work_item = nullptr;
    }
    return result;
}

typedef struct _ebpf_timer_work_item
{
    TP_TIMER* threadpool_timer;
    void (*work_item_routine)(_Inout_opt_ void* work_item_context);
    void* work_item_context;
} ebpf_timer_work_item_t;

void
_ebpf_timer_callback(_Inout_ TP_CALLBACK_INSTANCE* instance, _Inout_opt_ void* context, _Inout_ TP_TIMER* timer)
{
    ebpf_timer_work_item_t* timer_work_item = reinterpret_cast<ebpf_timer_work_item_t*>(context);
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(timer);
    if (timer_work_item) {
        timer_work_item->work_item_routine(timer_work_item->work_item_context);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_allocate_timer_work_item(
    _Outptr_ ebpf_timer_work_item_t** work_item,
    _In_ void (*work_item_routine)(_Inout_opt_ void* work_item_context),
    _Inout_opt_ void* work_item_context)
{
    *work_item = (ebpf_timer_work_item_t*)ebpf_allocate(sizeof(ebpf_timer_work_item_t));

    if (*work_item == nullptr) {
        goto Error;
    }

    (*work_item)->threadpool_timer = CreateThreadpoolTimer(_ebpf_timer_callback, *work_item, nullptr);
    if ((*work_item)->threadpool_timer == nullptr) {
        goto Error;
    }

    (*work_item)->work_item_routine = work_item_routine;
    (*work_item)->work_item_context = work_item_context;

    return EBPF_SUCCESS;

Error:
    if (*work_item != nullptr) {
        if ((*work_item)->threadpool_timer != nullptr) {
            CloseThreadpoolTimer((*work_item)->threadpool_timer);
        }

        ebpf_free(*work_item);
    }
    return EBPF_NO_MEMORY;
}

#define MICROSECONDS_PER_TICK 10
#define MICROSECONDS_PER_MILLISECOND 1000

void
ebpf_schedule_timer_work_item(_Inout_ ebpf_timer_work_item_t* timer, uint32_t elapsed_microseconds)
{
    int64_t due_time;
    due_time = -static_cast<int64_t>(elapsed_microseconds) * MICROSECONDS_PER_TICK;

    SetThreadpoolTimer(
        timer->threadpool_timer,
        reinterpret_cast<FILETIME*>(&due_time),
        0,
        elapsed_microseconds / MICROSECONDS_PER_MILLISECOND);
}

void
ebpf_free_timer_work_item(_Frees_ptr_opt_ ebpf_timer_work_item_t* work_item)
{
    if (!work_item) {
        return;
    }

    WaitForThreadpoolTimerCallbacks(work_item->threadpool_timer, true);
    CloseThreadpoolTimer(work_item->threadpool_timer);
    for (auto& dpc : _ebpf_emulated_dpcs) {
        dpc->flush_queue();
    }
    ebpf_free(work_item);
}

_Must_inspect_result_ ebpf_result_t
ebpf_guid_create(_Out_ GUID* new_guid)
{
    if (ebpf_fault_injection_inject_fault()) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    if (UuidCreate(new_guid) == RPC_S_OK) {
        return EBPF_SUCCESS;
    } else {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
}

int32_t
ebpf_log_function(_In_ void* context, _In_z_ const char* format_string, ...)
{
    UNREFERENCED_PARAMETER(context);

    va_list arg_start;
    va_start(arg_start, format_string);

    vprintf(format_string, arg_start);

    va_end(arg_start);
    return 0;
}

_Must_inspect_result_ ebpf_result_t
ebpf_access_check(
    _In_ const ebpf_security_descriptor_t* security_descriptor,
    ebpf_security_access_mask_t request_access,
    _In_ const ebpf_security_generic_mapping_t* generic_mapping)
{
    if (ebpf_fault_injection_inject_fault()) {
        return EBPF_ACCESS_DENIED;
    }

    ebpf_result_t result;
    HANDLE token = INVALID_HANDLE_VALUE;

    // Using BOOL to pass "AccessCheck" defined in Windows "securitybaseapi.h" file
    BOOL access_status = FALSE;
    unsigned long granted_access;
    PRIVILEGE_SET privilege_set;
    unsigned long privilege_set_size = sizeof(privilege_set);
    bool is_impersonating = false;

    if (!ImpersonateSelf(SecurityImpersonation)) {
        result = EBPF_ACCESS_DENIED;
        goto Done;
    }
    is_impersonating = true;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        result = EBPF_ACCESS_DENIED;
        goto Done;
    }

    if (!AccessCheck(
            const_cast<_SECURITY_DESCRIPTOR*>(security_descriptor),
            token,
            request_access,
            const_cast<GENERIC_MAPPING*>(generic_mapping),
            &privilege_set,
            &privilege_set_size,
            &granted_access,
            &access_status)) {
        unsigned long err = GetLastError();
        printf("LastError: %d\n", err);
        result = EBPF_ACCESS_DENIED;
    } else {
        result = access_status ? EBPF_SUCCESS : EBPF_ACCESS_DENIED;
    }

Done:
    if (token != INVALID_HANDLE_VALUE) {
        CloseHandle(token);
    }

    if (is_impersonating) {
        RevertToSelf();
    }
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_validate_security_descriptor(
    _In_ const ebpf_security_descriptor_t* security_descriptor, size_t security_descriptor_length)
{
    if (ebpf_fault_injection_inject_fault()) {
        return EBPF_NO_MEMORY;
    }

    ebpf_result_t result;
    SECURITY_DESCRIPTOR_CONTROL security_descriptor_control;
    unsigned long version;
    unsigned long length;
    if (!IsValidSecurityDescriptor(const_cast<_SECURITY_DESCRIPTOR*>(security_descriptor))) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if (!GetSecurityDescriptorControl(
            const_cast<_SECURITY_DESCRIPTOR*>(security_descriptor), &security_descriptor_control, &version)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    if ((security_descriptor_control & SE_SELF_RELATIVE) == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    length = GetSecurityDescriptorLength(const_cast<_SECURITY_DESCRIPTOR*>(security_descriptor));
    if (length != security_descriptor_length) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = EBPF_SUCCESS;

Done:
    return result;
}

uint32_t
ebpf_result_to_win32_error_code(ebpf_result_t result)
{
    static uint32_t (*RtlNtStatusToDosError)(NTSTATUS Status) = nullptr;
    if (!RtlNtStatusToDosError) {
        HMODULE ntdll = LoadLibrary(L"ntdll.dll");
        if (!ntdll) {
            return ERROR_OUTOFMEMORY;
        }
        RtlNtStatusToDosError =
            reinterpret_cast<decltype(RtlNtStatusToDosError)>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    }
    return RtlNtStatusToDosError(ebpf_result_to_ntstatus(result));
}

long
ebpf_platform_printk(_In_z_ const char* format, va_list arg_list)
{
    int bytes_written = vprintf(format, arg_list);
    if (bytes_written >= 0) {
        putchar('\n');
        bytes_written++;
    }
    return bytes_written;
}

_Must_inspect_result_ ebpf_result_t
ebpf_update_global_helpers(
    _In_reads_(helper_info_count) ebpf_helper_function_prototype_t* helper_info, uint32_t helper_info_count)
{
    UNREFERENCED_PARAMETER(helper_info);
    UNREFERENCED_PARAMETER(helper_info_count);
    return EBPF_SUCCESS;
}

uint32_t
ebpf_platform_process_id()
{
    return GetCurrentProcessId();
}

uint32_t
ebpf_platform_thread_id()
{
    return GetCurrentThreadId();
}

_IRQL_requires_max_(PASSIVE_LEVEL) _Must_inspect_result_ ebpf_result_t
    ebpf_platform_get_authentication_id(_Out_ uint64_t* authentication_id)
{
    // GetTokenInformation OS API can fail with return value of zero.
    if (ebpf_fault_injection_inject_fault()) {
        return EBPF_NO_MEMORY;
    }

    ebpf_result_t return_value = EBPF_SUCCESS;
    uint32_t error;
    TOKEN_GROUPS_AND_PRIVILEGES* privileges = nullptr;
    uint32_t size = 0;
    HANDLE thread_token_handle = GetCurrentThreadEffectiveToken();

    bool result = GetTokenInformation(thread_token_handle, TokenGroupsAndPrivileges, nullptr, 0, (unsigned long*)&size);
    error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, GetTokenInformation);
        return win32_error_code_to_ebpf_result(GetLastError());
    }

    privileges = (TOKEN_GROUPS_AND_PRIVILEGES*)ebpf_allocate(size);
    if (privileges == nullptr) {
        return EBPF_NO_MEMORY;
    }

    result =
        GetTokenInformation(thread_token_handle, TokenGroupsAndPrivileges, privileges, size, (unsigned long*)&size);
    if (result == false) {
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, GetTokenInformation);
        return_value = win32_error_code_to_ebpf_result(GetLastError());
        goto Exit;
    }

    *authentication_id = *(uint64_t*)&privileges->AuthenticationId;

Exit:
    ebpf_free(privileges);
    return return_value;
}

_IRQL_requires_max_(HIGH_LEVEL) _IRQL_raises_(new_irql) _IRQL_saves_ uint8_t ebpf_raise_irql(uint8_t new_irql)
{
    UNREFERENCED_PARAMETER(new_irql);
    return 0;
}

_IRQL_requires_max_(HIGH_LEVEL) void ebpf_lower_irql(_In_ _Notliteral_ _IRQL_restores_ uint8_t old_irql)
{
    UNREFERENCED_PARAMETER(old_irql);
}

bool
ebpf_should_yield_processor()
{
    return false;
}

void
ebpf_get_execution_context_state(_Out_ ebpf_execution_context_state_t* state)
{
    if (ebpf_non_preemptible) {
        state->current_irql = DISPATCH_LEVEL;
        state->id.cpu = ebpf_get_current_cpu();
    } else {
        state->current_irql = PASSIVE_LEVEL;
        state->id.thread = GetCurrentThreadId();
    }
}

uint8_t
ebpf_get_current_irql()
{
    return ebpf_non_preemptible ? DISPATCH_LEVEL : PASSIVE_LEVEL;
}

typedef struct _ebpf_semaphore
{
    HANDLE semaphore;
} ebpf_semaphore_t;

_Must_inspect_result_ ebpf_result_t
ebpf_semaphore_create(_Outptr_ ebpf_semaphore_t** semaphore, int initial_count, int maximum_count)
{
    *semaphore = (ebpf_semaphore_t*)ebpf_allocate(sizeof(ebpf_semaphore_t));
    if (*semaphore == nullptr) {
        return EBPF_NO_MEMORY;
    }

    (*semaphore)->semaphore = CreateSemaphore(nullptr, initial_count, maximum_count, nullptr);
    if ((*semaphore)->semaphore == INVALID_HANDLE_VALUE) {
        ebpf_free(*semaphore);
        *semaphore = nullptr;
        return EBPF_NO_MEMORY;
    }
    return EBPF_SUCCESS;
}

void
ebpf_semaphore_destroy(_Frees_ptr_opt_ ebpf_semaphore_t* semaphore)
{
    if (semaphore) {
        ::CloseHandle(semaphore->semaphore);
        ebpf_free(semaphore);
    }
}

void
ebpf_semaphore_wait(_In_ ebpf_semaphore_t* semaphore)
{
    WaitForSingleObject(semaphore->semaphore, INFINITE);
}

void
ebpf_semaphore_release(_In_ ebpf_semaphore_t* semaphore)
{
    ReleaseSemaphore(semaphore->semaphore, 1, nullptr);
}

void
ebpf_enter_critical_region()
{
    // This is a no-op for the user mode implementation.
}

void
ebpf_leave_critical_region()
{
    // This is a no-op for the user mode implementation.
}
