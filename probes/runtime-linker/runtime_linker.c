#include <stddef.h>
#include <stdint.h>

enum {
    AT_NULL = 0,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_ENTRY = 9,
    AT_RANDOM = 25,
    AT_EXECFN = 31,
    SYS_WRITE = 1,
    SYS_EXIT_GROUP = 231,
};

static const char pass_marker[] = "ARACH_C2_RUNTIME_LINKER_PASS\n";
static const char enter_marker[] = "ARACH_C2_RUNTIME_LINKER_ENTER\n";
static const char stack_failure[] = "ARACH_C2_LINKER_STACK_FAIL\n";
static const char headers_failure[] = "ARACH_C2_LINKER_HEADERS_FAIL\n";
static const char base_failure[] = "ARACH_C2_LINKER_BASE_FAIL\n";
static const char pointers_failure[] = "ARACH_C2_LINKER_POINTERS_FAIL\n";
static const char path_failure[] = "ARACH_C2_LINKER_PATH_FAIL\n";
static const char random_failure[] = "ARACH_C2_LINKER_RANDOM_FAIL\n";
static const char expected_path[] = "/exec-target";

extern void _start(void);

static long syscall3(uint64_t number, uint64_t first, uint64_t second,
                     uint64_t third) {
    register uint64_t rax __asm__("rax") = number;
    register uint64_t rdi __asm__("rdi") = first;
    register uint64_t rsi __asm__("rsi") = second;
    register uint64_t rdx __asm__("rdx") = third;
    __asm__ volatile("syscall"
                     : "+a"(rax)
                     : "D"(rdi), "S"(rsi), "d"(rdx)
                     : "rcx", "r11", "memory");
    return (long)rax;
}

static void fail(void) {
    (void)syscall3(SYS_EXIT_GROUP, 127, 0, 0);
    for (;;) {
        __asm__ volatile("pause");
    }
}

static void fail_with(const char *marker, size_t length) {
    (void)syscall3(SYS_WRITE, 2, (uintptr_t)marker, length);
    fail();
}

static int bytes_equal(const char *left, const char *right, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

uintptr_t arach_runtime_linker_start(const uintptr_t *stack) {
    if (syscall3(SYS_WRITE, 1, (uintptr_t)enter_marker,
                 sizeof(enter_marker) - 1) != (long)(sizeof(enter_marker) - 1)) {
        fail();
    }
    if (stack == NULL || stack[0] != 1) {
        fail_with(stack_failure, sizeof(stack_failure) - 1);
    }
    const uintptr_t *cursor = stack + 1;
    if (*cursor == 0) {
        fail_with(stack_failure, sizeof(stack_failure) - 1);
    }
    size_t vector_entries = 0;
    while (*cursor != 0 && vector_entries < 64) {
        ++cursor;
        ++vector_entries;
    }
    if (*cursor != 0) {
        fail_with(stack_failure, sizeof(stack_failure) - 1);
    }
    ++cursor;
    vector_entries = 0;
    while (*cursor != 0 && vector_entries < 64) {
        ++cursor;
        ++vector_entries;
    }
    if (*cursor != 0) {
        fail_with(stack_failure, sizeof(stack_failure) - 1);
    }
    ++cursor;

    uintptr_t program_headers = 0;
    uintptr_t program_header_size = 0;
    uintptr_t program_header_count = 0;
    uintptr_t page_size = 0;
    uintptr_t runtime_linker_base = 0;
    uintptr_t executable_entry = 0;
    uintptr_t random_address = 0;
    uintptr_t executable_path = 0;
    int found_terminator = 0;
    for (size_t entries = 0; entries < 64; ++entries) {
        const uintptr_t kind = cursor[0];
        const uintptr_t value = cursor[1];
        cursor += 2;
        if (kind == AT_NULL) {
            found_terminator = 1;
            break;
        }
        switch (kind) {
        case AT_PHDR:
            program_headers = value;
            break;
        case AT_PHENT:
            program_header_size = value;
            break;
        case AT_PHNUM:
            program_header_count = value;
            break;
        case AT_PAGESZ:
            page_size = value;
            break;
        case AT_BASE:
            runtime_linker_base = value;
            break;
        case AT_ENTRY:
            executable_entry = value;
            break;
        case AT_RANDOM:
            random_address = value;
            break;
        case AT_EXECFN:
            executable_path = value;
            break;
        default:
            break;
        }
    }

    const uintptr_t own_entry = (uintptr_t)&_start;
    if (!found_terminator || program_headers == 0 || program_header_size != 56 ||
        program_header_count < 4 || page_size != 4096) {
        fail_with(headers_failure, sizeof(headers_failure) - 1);
    }
    if (runtime_linker_base == 0 || own_entry < runtime_linker_base ||
        own_entry >= runtime_linker_base + (64 * 1024)) {
        fail_with(base_failure, sizeof(base_failure) - 1);
    }
    if (executable_entry == 0 || random_address == 0 || executable_path == 0) {
        fail_with(pointers_failure, sizeof(pointers_failure) - 1);
    }
    if (!bytes_equal((const char *)executable_path, expected_path,
                     sizeof(expected_path))) {
        fail_with(path_failure, sizeof(path_failure) - 1);
    }
    const uint8_t *random = (const uint8_t *)random_address;
    uint8_t aggregate = 0;
    for (size_t index = 0; index < 16; ++index) {
        aggregate |= random[index];
    }
    if (aggregate == 0 ||
        syscall3(SYS_WRITE, 1, (uintptr_t)pass_marker,
                 sizeof(pass_marker) - 1) != (long)(sizeof(pass_marker) - 1)) {
        fail_with(random_failure, sizeof(random_failure) - 1);
    }
    return executable_entry;
}
