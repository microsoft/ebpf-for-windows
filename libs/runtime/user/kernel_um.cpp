// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_fault_injection.h"
#include "ebpf_platform.h"
#include "kernel_um.h"

#include <condition_variable>
#include <map>
#include <mutex>
#include <tuple>

/***
 * @brief This following class implements a mock of the Windows Kernel's rundown reference implementation.
 * 1) It uses a map to track the number of references to a given EX_RUNDOWN_REF structure.
 * 2) The address of the EX_RUNDOWN_REF structure is used as the key to the map.
 * 3) A single condition variable is used to wait for the ref count of any EX_RUNDOWN_REF structure to reach 0.
 * 4) The class is a singleton and is created during static initialization and destroyed during static destruction.
 */
typedef class _rundown_ref_table
{
  private:
    static std::unique_ptr<_rundown_ref_table> _instance;

  public:
    // The constructor and destructor should be private to ensure that the class is a singleton, but that is not
    // possible because the singleton instance is stored in a unique_ptr which requires the constructor to be public.
    // The instance of the class can be accessed using the instance() method.
    _rundown_ref_table() = default;
    ~_rundown_ref_table() = default;

    /**
     * @brief Get the singleton instance of the rundown ref table.
     *
     * @return The singleton instance of the rundown ref table.
     */
    static _rundown_ref_table&
    instance()
    {
        return *_instance;
    }

    /**
     * @brief Initialize the rundown ref table entry for the given context.
     *
     * @param[in] context The address of a EX_RUNDOWN_REF structure.
     */
    void
    initialize_rundown_ref(_In_ const void* context)
    {
        std::unique_lock lock(_lock);

        // Re-initialize the entry if it already exists.
        if (_rundown_ref_counts.find((uint64_t)context) != _rundown_ref_counts.end()) {
            _rundown_ref_counts.erase((uint64_t)context);
        }

        _rundown_ref_counts[(uint64_t)context] = {false, 0};
    }

    /**
     * @brief Reinitialize the rundown ref table entry for the given context.
     *
     * @param[in] context The address of a previously run down EX_RUNDOWN_REF structure.
     */
    void
    reinitialize_rundown_ref(_In_ const void* context)
    {
        std::unique_lock lock(_lock);

        // Fail if the entry is not initialized.
        if (_rundown_ref_counts.find((uint64_t)context) == _rundown_ref_counts.end()) {
            throw std::runtime_error("rundown ref table not initialized");
        }

        auto& [rundown, ref_count] = _rundown_ref_counts[(uint64_t)context];

        // Check if the entry is not rundown.
        if (!rundown) {
            throw std::runtime_error("rundown ref table not rundown");
        }

        if (ref_count != 0) {
            throw std::runtime_error("rundown ref table corruption");
        }

        rundown = false;
    }

    /**
     * @brief Acquire a rundown ref for the given context.
     *
     * @param[in] context The address of a EX_RUNDOWN_REF structure.
     * @retval true Rundown has not started.
     * @retval false Rundown has started.
     */
    bool
    acquire_rundown_ref(_In_ const void* context)
    {
        std::unique_lock lock(_lock);

        // Fail if the entry is not initialized.
        if (_rundown_ref_counts.find((uint64_t)context) == _rundown_ref_counts.end()) {
            throw std::runtime_error("rundown ref table not initialized");
        }

        // Check if the entry is already rundown.
        if (std::get<0>(_rundown_ref_counts[(uint64_t)context])) {
            return false;
        }

        // Increment the ref count if the entry is not rundown.
        std::get<1>(_rundown_ref_counts[(uint64_t)context])++;

        return true;
    }

    /**
     * @brief Release a rundown ref for the given context.
     *
     * @param[in] context The address of a EX_RUNDOWN_REF structure.
     */
    void
    release_rundown_ref(_In_ const void* context)
    {
        std::unique_lock lock(_lock);

        // Fail if the entry is not initialized.
        if (_rundown_ref_counts.find((uint64_t)context) == _rundown_ref_counts.end()) {
            throw std::runtime_error("rundown ref table not initialized");
        }

        if (std::get<1>(_rundown_ref_counts[(uint64_t)context]) == 0) {
            throw std::runtime_error("rundown ref table already released");
        }

        std::get<1>(_rundown_ref_counts[(uint64_t)context])--;

        if (std::get<1>(_rundown_ref_counts[(uint64_t)context]) == 0) {
            _rundown_ref_cv.notify_all();
        }
    }

    /**
     * @brief Wait for the rundown ref count to reach 0 for the given context.
     *
     * @param[in] context The address of a EX_RUNDOWN_REF structure.
     */
    void
    wait_for_rundown_ref(_In_ const void* context)
    {
        std::unique_lock lock(_lock);

        // Fail if the entry is not initialized.
        if (_rundown_ref_counts.find((uint64_t)context) == _rundown_ref_counts.end()) {
            throw std::runtime_error("rundown ref table not initialized");
        }

        auto& [rundown, ref_count] = _rundown_ref_counts[(uint64_t)context];
        rundown = true;
        // Wait for the ref count to reach 0.
        _rundown_ref_cv.wait(lock, [&ref_count] { return ref_count == 0; });
    }

  private:
    std::mutex _lock;
    std::map<uint64_t, std::tuple<bool, uint64_t>> _rundown_ref_counts;
    std::condition_variable _rundown_ref_cv;
} rundown_ref_table_t;

/**
 * @brief The singleton instance of the rundown ref table. Created during static initialization and destroyed during
 * static destruction.
 */
std::unique_ptr<_rundown_ref_table> rundown_ref_table_t::_instance = std::make_unique<rundown_ref_table_t>();

typedef struct _IO_WORKITEM
{
    DEVICE_OBJECT* device;
    PTP_WORK work_item;
    IO_WORKITEM_ROUTINE* routine;
    void* context;
} IO_WORKITEM;

typedef unsigned long PFN_NUMBER;
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12L

#define PAGE_ALIGN(Va) ((void*)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define BYTE_OFFSET(Va) ((unsigned long)((LONG_PTR)(Va) & (PAGE_SIZE - 1)))
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va, size)                                                                \
    (((((size)-1) >> PAGE_SHIFT) +                                                                              \
      (((((unsigned long)(size - 1) & (PAGE_SIZE - 1)) + (PtrToUlong(Va) & (PAGE_SIZE - 1)))) >> PAGE_SHIFT)) + \
     1L)

static GENERIC_MAPPING _mapping = {1, 1, 1};

static SE_EXPORTS _SeExports = {0};
PSE_EXPORTS SeExports = &_SeExports;

unsigned long
MmGetMdlByteCount(_In_ MDL* mdl)
{
    return mdl->byte_count;
}

#define MmGetMdlByteOffset(mdl) ((mdl)->byte_offset)
#define MmGetMdlBaseVa(mdl) ((mdl)->start_va)
#define MmGetMdlVirtualAddress(mdl) ((void*)((PCHAR)((mdl)->start_va) + (mdl)->byte_offset))
#define MmInitializeMdl(mdl, base_va, length)                                                                     \
    {                                                                                                             \
        (mdl)->next = (PMDL)NULL;                                                                                 \
        (mdl)->size =                                                                                             \
            (uint16_t)(sizeof(MDL) + (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES((base_va), (length)))); \
        (mdl)->flags = 0;                                                                                         \
        (mdl)->start_va = (void*)PAGE_ALIGN((base_va));                                                           \
        (mdl)->byte_offset = BYTE_OFFSET((base_va));                                                              \
        (mdl)->byte_count = (ULONG)(length);                                                                      \
    }

unsigned long __cdecl DbgPrintEx(
    _In_ unsigned long component_id, _In_ unsigned long level, _In_z_ _Printf_format_string_ PCSTR format, ...)
{
    UNREFERENCED_PARAMETER(component_id);
    UNREFERENCED_PARAMETER(level);
    UNREFERENCED_PARAMETER(format);
    return MAXULONG32;
}

void
ExInitializeRundownProtection(_Out_ EX_RUNDOWN_REF* rundown_ref)
{
#pragma warning(push)
#pragma warning(suppress : 6001) // Uninitialized memory. The rundown_ref is used as a key in a map and is not
                                 // dereferenced.
    rundown_ref_table_t::instance().initialize_rundown_ref(rundown_ref);
#pragma warning(pop)
}

void
ExReInitializeRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    rundown_ref_table_t::instance().reinitialize_rundown_ref(rundown_ref);
}

void
ExWaitForRundownProtectionRelease(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    rundown_ref_table_t::instance().wait_for_rundown_ref(rundown_ref);
}

BOOLEAN
ExAcquireRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    if (rundown_ref_table_t::instance().acquire_rundown_ref(rundown_ref)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

void
ExReleaseRundownProtection(_Inout_ EX_RUNDOWN_REF* rundown_ref)
{
    rundown_ref_table_t::instance().release_rundown_ref(rundown_ref);
}

_Acquires_exclusive_lock_(push_lock->lock) void ExAcquirePushLockExclusiveEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    AcquireSRWLockExclusive(&push_lock->lock);
}

_Acquires_shared_lock_(push_lock->lock) void ExAcquirePushLockSharedEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_PUSH_LOCK* push_lock,
    _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    AcquireSRWLockShared(&push_lock->lock);
}

_Releases_exclusive_lock_(push_lock->lock) void ExReleasePushLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    ReleaseSRWLockExclusive(&push_lock->lock);
}

_Releases_shared_lock_(push_lock->lock) void ExReleasePushLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_PUSH_LOCK* push_lock, _In_ unsigned long flags)
{
    UNREFERENCED_PARAMETER(flags);
    ReleaseSRWLockShared(&push_lock->lock);
}

_Acquires_exclusive_lock_(spin_lock->lock) KIRQL
    ExAcquireSpinLockExclusiveEx(_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
                                     EX_SPIN_LOCK* spin_lock)
{
    AcquireSRWLockExclusive(&spin_lock->lock);
    return PASSIVE_LEVEL;
}

_Acquires_exclusive_lock_(spin_lock->lock) void ExAcquireSpinLockExclusiveAtDpcLevelEx(
    _Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock)
{
    AcquireSRWLockExclusive(&spin_lock->lock);
}

_Acquires_shared_lock_(spin_lock->lock) KIRQL
    ExAcquireSpinLockSharedEx(_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
                                  EX_SPIN_LOCK* spin_lock)
{
    AcquireSRWLockShared(&spin_lock->lock);
    return PASSIVE_LEVEL;
}

_Releases_exclusive_lock_(spin_lock->lock) void ExReleaseSpinLockExclusiveEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock, KIRQL old_irql)
{
    UNREFERENCED_PARAMETER(old_irql);
    ReleaseSRWLockExclusive(&spin_lock->lock);
}

_Releases_exclusive_lock_(spin_lock->lock) void ExReleaseSpinLockExclusiveFromDpcLevelEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock)
{
    ReleaseSRWLockExclusive(&spin_lock->lock);
}

_Releases_shared_lock_(spin_lock->lock) void ExReleaseSpinLockSharedEx(
    _Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) EX_SPIN_LOCK* spin_lock, KIRQL old_irql)
{
    UNREFERENCED_PARAMETER(old_irql);
    ReleaseSRWLockShared(&spin_lock->lock);
}

void*
ExAllocatePoolUninitialized(_In_ POOL_TYPE pool_type, _In_ size_t number_of_bytes, _In_ unsigned long tag)
{
    UNREFERENCED_PARAMETER(pool_type);
    UNREFERENCED_PARAMETER(tag);
    return ebpf_allocate(number_of_bytes);
}

void
ExFreePool(void* p)
{
    ebpf_free(p);
}

void
ExInitializePushLock(_Out_ EX_PUSH_LOCK* push_lock)
{
    push_lock->lock = SRWLOCK_INIT;
}

void
FatalListEntryError(_In_ void* p1, _In_ void* p2, _In_ void* p3)
{
    UNREFERENCED_PARAMETER(p1);
    UNREFERENCED_PARAMETER(p2);
    UNREFERENCED_PARAMETER(p3);
    ebpf_assert("FatalListEntryError");
}

MDL*
IoAllocateMdl(
    _In_opt_ __drv_aliasesMem void* virtual_address,
    _In_ unsigned long length,
    _In_ BOOLEAN secondary_buffer,
    _In_ BOOLEAN charge_quota,
    _Inout_opt_ IRP* irp)
{
    // Skip Fault Injection as it is already added in ebpf_allocate.
    PMDL mdl;

    UNREFERENCED_PARAMETER(secondary_buffer);
    UNREFERENCED_PARAMETER(charge_quota);
    UNREFERENCED_PARAMETER(irp);

    mdl = reinterpret_cast<MDL*>(ebpf_allocate(sizeof(MDL)));
    if (mdl == NULL) {
        return mdl;
    }
#pragma warning(push)
#pragma warning(disable : 26451)
    MmInitializeMdl(mdl, virtual_address, length);
#pragma warning(pop)

    return mdl;
}

void NTAPI
io_work_item_wrapper(_Inout_ PTP_CALLBACK_INSTANCE instance, _Inout_opt_ void* context, _Inout_ PTP_WORK work)
{
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(work);
    auto work_item = reinterpret_cast<const IO_WORKITEM*>(context);
    if (work_item) {
        work_item->routine(work_item->device, work_item->context);
    }
}

PIO_WORKITEM
IoAllocateWorkItem(_In_ DEVICE_OBJECT* device_object)
{
    // Skip Fault Injection as it is already added in ebpf_allocate.
    auto work_item = reinterpret_cast<IO_WORKITEM*>(ebpf_allocate(sizeof(IO_WORKITEM)));
    if (!work_item) {
        return nullptr;
    }
    work_item->device = device_object;
    work_item->work_item = CreateThreadpoolWork(io_work_item_wrapper, work_item, nullptr);
    if (work_item->work_item == nullptr) {
        ebpf_free(work_item);
        work_item = nullptr;
    }
    return work_item;
}

void
IoQueueWorkItem(
    _Inout_ __drv_aliasesMem IO_WORKITEM* io_workitem,
    _In_ IO_WORKITEM_ROUTINE* worker_routine,
    _In_ WORK_QUEUE_TYPE queue_type,
    _In_opt_ __drv_aliasesMem void* context)
{
    UNREFERENCED_PARAMETER(queue_type);
    io_workitem->routine = worker_routine;
    io_workitem->context = context;
    SubmitThreadpoolWork(io_workitem->work_item);
}

void
IoFreeWorkItem(_In_ __drv_freesMem(Mem) PIO_WORKITEM io_workitem)
{
    if (io_workitem) {
        CloseThreadpoolWork(io_workitem->work_item);
        ebpf_free(io_workitem);
    }
}

void
IoFreeMdl(MDL* mdl)
{
    ebpf_free(mdl);
}

void
KeEnterCriticalRegion(void)
{}

void
KeLeaveCriticalRegion(void)
{}

void
KeInitializeSpinLock(_Out_ PKSPIN_LOCK spin_lock)
{
    auto lock = reinterpret_cast<SRWLOCK*>(spin_lock);
    *lock = SRWLOCK_INIT;
}

_Requires_lock_not_held_(*spin_lock) _Acquires_lock_(*spin_lock) _IRQL_requires_max_(DISPATCH_LEVEL) KIRQL
    KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK spin_lock)
{
    // Skip Fault Injection.
    auto lock = reinterpret_cast<SRWLOCK*>(spin_lock);
    AcquireSRWLockExclusive(lock);
    return 0;
}

_Requires_lock_held_(*spin_lock) _Releases_lock_(*spin_lock) _IRQL_requires_(DISPATCH_LEVEL) void KeReleaseSpinLock(
    _Inout_ PKSPIN_LOCK spin_lock, _In_ _IRQL_restores_ KIRQL new_irql)
{
    UNREFERENCED_PARAMETER(new_irql);
    auto lock = reinterpret_cast<SRWLOCK*>(spin_lock);
    ReleaseSRWLockExclusive(lock);
}

void
MmBuildMdlForNonPagedPool(_Inout_ MDL* memory_descriptor_list)
{
    UNREFERENCED_PARAMETER(memory_descriptor_list);
}

void*
MmGetSystemAddressForMdlSafe(
    _Inout_ MDL* mdl,
    _In_ unsigned long page_priority // MM_PAGE_PRIORITY logically OR'd with MdlMapping*
)
{
    if (ebpf_fault_injection_inject_fault()) {
        return nullptr;
    }

    UNREFERENCED_PARAMETER(page_priority);
    return ((void*)((PUCHAR)(mdl)->start_va + (mdl)->byte_offset));
}

NTSTATUS
RtlULongAdd(
    _In_ unsigned long augend,
    _In_ unsigned long addend,
    _Out_ _Deref_out_range_(==, augend + addend) unsigned long* result)
{
    // Skip Fault Injection.
    *result = augend + addend;
    return STATUS_SUCCESS;
}

unsigned long long
QueryInterruptTimeEx()
{
    unsigned long long time = 0;
    QueryInterruptTime(&time);

    return time;
}

PGENERIC_MAPPING
IoGetFileObjectGenericMapping() { return &_mapping; }

NTSTATUS
RtlCreateAcl(_Out_ PACL Acl, unsigned long AclLength, unsigned long AclRevision)
{
    // Skip Fault Injection.
    UNREFERENCED_PARAMETER(Acl);
    UNREFERENCED_PARAMETER(AclRevision);

    if (AclLength < sizeof(ACL)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    memset(Acl, 0, AclLength);

    return STATUS_SUCCESS;
}

VOID
RtlMapGenericMask(_Inout_ PACCESS_MASK AccessMask, _In_ const GENERIC_MAPPING* GenericMapping)
{
    UNREFERENCED_PARAMETER(AccessMask);
    UNREFERENCED_PARAMETER(GenericMapping);
}

unsigned long
RtlLengthSid(_In_ PSID Sid)
{
    UNREFERENCED_PARAMETER(Sid);
    return (unsigned long)sizeof(SID);
}

NTSTATUS
RtlAddAccessAllowedAce(_Inout_ PACL Acl, _In_ unsigned long AceRevision, _In_ ACCESS_MASK AccessMask, _In_ PSID Sid)
{
    if (ebpf_fault_injection_inject_fault()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UNREFERENCED_PARAMETER(Acl);
    UNREFERENCED_PARAMETER(AceRevision);
    UNREFERENCED_PARAMETER(AccessMask);
    UNREFERENCED_PARAMETER(Sid);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN DaclPresent,
    _In_opt_ PACL Dacl,
    _In_ BOOLEAN DaclDefaulted)
{
    // Skip Fault Injection.
    UNREFERENCED_PARAMETER(SecurityDescriptor);
    UNREFERENCED_PARAMETER(DaclPresent);
    UNREFERENCED_PARAMETER(Dacl);
    UNREFERENCED_PARAMETER(DaclDefaulted);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlCreateSecurityDescriptor(_Out_ PSECURITY_DESCRIPTOR SecurityDescriptor, _In_ unsigned long Revision)
{
    // Skip Fault Injection.
    UNREFERENCED_PARAMETER(Revision);
    memset(SecurityDescriptor, 0, sizeof(SECURITY_DESCRIPTOR));

    return STATUS_SUCCESS;
}

BOOLEAN
SeAccessCheckFromState(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PTOKEN_ACCESS_INFORMATION PrimaryTokenInformation,
    _In_opt_ PTOKEN_ACCESS_INFORMATION ClientTokenInformation,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK PreviouslyGrantedAccess,
    _Outptr_opt_result_maybenull_ PPRIVILEGE_SET* Privileges,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ NTSTATUS* AccessStatus)
{
    if (Privileges != NULL) {
        *Privileges = NULL;
    }
    *GrantedAccess = DesiredAccess;

    if (ebpf_fault_injection_inject_fault()) {
        *AccessStatus = STATUS_ACCESS_DENIED;
        return false;
    }

    UNREFERENCED_PARAMETER(SecurityDescriptor);
    UNREFERENCED_PARAMETER(PrimaryTokenInformation);
    UNREFERENCED_PARAMETER(ClientTokenInformation);
    UNREFERENCED_PARAMETER(PreviouslyGrantedAccess);
    UNREFERENCED_PARAMETER(GenericMapping);
    UNREFERENCED_PARAMETER(AccessMode);

    *AccessStatus = STATUS_SUCCESS;

    return true;
}

KIRQL
KeGetCurrentIrql() { return PASSIVE_LEVEL; }

HANDLE
PsGetCurrentProcessId() { return (HANDLE)(uintptr_t)GetCurrentProcessId(); }

HANDLE
PsGetCurrentThreadId() { return (HANDLE)(uintptr_t)GetCurrentThreadId(); }
