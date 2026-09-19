// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <bpf/bpf.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <crtdbg.h>
#include <io.h>
#include <stdlib.h>
#define close _close
#else
#include <unistd.h>
#endif

typedef int (*behavior_test_fn)(int map_fd, uint32_t* key, uint32_t* value);

typedef struct behavior_test
{
    const char* name;
    behavior_test_fn run;
    int requires_map;
} behavior_test_t;

static int
lookup_invalid_fd(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)map_fd;
    return bpf_map_lookup_elem(-1, key, value);
}

static int
update_invalid_fd(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)map_fd;
    return bpf_map_update_elem(-1, key, value, BPF_ANY);
}

static int
delete_invalid_fd(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)map_fd;
    (void)value;
    return bpf_map_delete_elem(-1, key);
}

static int
next_key_invalid_fd(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)map_fd;
    return bpf_map_get_next_key(-1, key, value);
}

static int
lookup_null_key(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)key;
    return bpf_map_lookup_elem(map_fd, NULL, value);
}

static int
lookup_null_value(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)value;
    return bpf_map_lookup_elem(map_fd, key, NULL);
}

static int
update_null_key(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)key;
    return bpf_map_update_elem(map_fd, NULL, value, BPF_ANY);
}

static int
update_null_value(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)value;
    return bpf_map_update_elem(map_fd, key, NULL, BPF_ANY);
}

static int
update_invalid_flags(int map_fd, uint32_t* key, uint32_t* value)
{
    return bpf_map_update_elem(map_fd, key, value, UINT64_MAX);
}

static int
delete_null_key(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)key;
    (void)value;
    return bpf_map_delete_elem(map_fd, NULL);
}

static int
next_key_null_output(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)key;
    (void)value;
    return bpf_map_get_next_key(map_fd, NULL, NULL);
}

static int
next_key_null_key(int map_fd, uint32_t* key, uint32_t* value)
{
    (void)key;
    return bpf_map_get_next_key(map_fd, NULL, value);
}

static const behavior_test_t tests[] = {
    {"lookup.invalid_fd", lookup_invalid_fd, 0},
    {"update.invalid_fd", update_invalid_fd, 0},
    {"delete.invalid_fd", delete_invalid_fd, 0},
    {"next_key.invalid_fd", next_key_invalid_fd, 0},
    {"lookup.null_key", lookup_null_key, 1},
    {"lookup.null_value", lookup_null_value, 1},
    {"update.null_key", update_null_key, 1},
    {"update.null_value", update_null_value, 1},
    {"update.invalid_flags", update_invalid_flags, 1},
    {"delete.null_key", delete_null_key, 1},
    {"next_key.null_output", next_key_null_output, 1},
    {"next_key.null_key", next_key_null_key, 1},
};

int
main(int argc, char** argv)
{
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    const behavior_test_t* test = NULL;
    uint32_t key = 0;
    uint32_t value = 1;
    int map_fd = -1;
    int result;
    int saved_errno;
    size_t index;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <test-name>\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "--list") == 0) {
        for (index = 0; index < sizeof(tests) / sizeof(tests[0]); index++) {
            printf("%s\n", tests[index].name);
        }
        return 0;
    }

    for (index = 0; index < sizeof(tests) / sizeof(tests[0]); index++) {
        if (strcmp(argv[1], tests[index].name) == 0) {
            test = &tests[index];
            break;
        }
    }

    if (test == NULL) {
        fprintf(stderr, "unknown test: %s\n", argv[1]);
        return 2;
    }

    if (test->requires_map) {
        errno = 0;
        map_fd = bpf_map_create(
            BPF_MAP_TYPE_ARRAY, "behavior_test", sizeof(key), sizeof(value), 1, NULL);
        if (map_fd < 0) {
            printf("setup.map_create\t%d\t%d\n", map_fd, errno);
            return 1;
        }
    }

    errno = 0;
    result = test->run(map_fd, &key, &value);
    saved_errno = errno;

    printf("%s\t%d\t%d\n", test->name, result, saved_errno);
    if (map_fd >= 0) {
        close(map_fd);
    }
    return 0;
}
