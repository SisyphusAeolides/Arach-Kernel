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
    SYS_READ = 0,
    SYS_WRITE = 1,
    SYS_OPEN = 2,
    SYS_CLOSE = 3,
    SYS_LSEEK = 8,
    SYS_MMAP = 9,
    SYS_MPROTECT = 10,
    SYS_MUNMAP = 11,
    SYS_EXIT_GROUP = 231,
    O_RDONLY = 0,
    SEEK_SET = 0,
    SEEK_END = 2,
    PROT_READ = 1,
    PROT_WRITE = 2,
    PROT_EXEC = 4,
    MAP_PRIVATE = 2,
    ELF_CLASS_64 = 2,
    ELF_DATA_LITTLE_ENDIAN = 1,
    ELF_VERSION_CURRENT = 1,
    ELF_TYPE_SHARED_OBJECT = 3,
    ELF_MACHINE_X86_64 = 62,
    PROGRAM_LOAD = 1,
    PROGRAM_DYNAMIC = 2,
    PROGRAM_HEADERS = 6,
    PROGRAM_EXECUTABLE = 1,
    PROGRAM_WRITABLE = 2,
    PROGRAM_READABLE = 4,
    DYNAMIC_NULL = 0,
    DYNAMIC_NEEDED = 1,
    DYNAMIC_PLT_RELOCATION_SIZE = 2,
    DYNAMIC_PLT_GOT = 3,
    DYNAMIC_HASH = 4,
    DYNAMIC_STRING_TABLE = 5,
    DYNAMIC_SYMBOL_TABLE = 6,
    DYNAMIC_RELA = 7,
    DYNAMIC_RELA_SIZE = 8,
    DYNAMIC_RELA_ENTRY = 9,
    DYNAMIC_STRING_SIZE = 10,
    DYNAMIC_SYMBOL_ENTRY = 11,
    DYNAMIC_INIT = 12,
    DYNAMIC_FINI = 13,
    DYNAMIC_SONAME = 14,
    DYNAMIC_SYMBOLIC = 16,
    DYNAMIC_REL = 17,
    DYNAMIC_REL_SIZE = 18,
    DYNAMIC_REL_ENTRY = 19,
    DYNAMIC_PLT_RELOCATION_TYPE = 20,
    DYNAMIC_DEBUG = 21,
    DYNAMIC_JUMP_RELOCATION = 23,
    DYNAMIC_TEXT_RELOCATION = 22,
    DYNAMIC_BIND_NOW = 24,
    DYNAMIC_INIT_ARRAY = 25,
    DYNAMIC_FINI_ARRAY = 26,
    DYNAMIC_INIT_ARRAY_SIZE = 27,
    DYNAMIC_FINI_ARRAY_SIZE = 28,
    DYNAMIC_RUNPATH = 29,
    DYNAMIC_FLAGS = 30,
    DYNAMIC_PREINIT_ARRAY = 32,
    DYNAMIC_PREINIT_ARRAY_SIZE = 33,
    DYNAMIC_RELR_SIZE = 35,
    DYNAMIC_RELR = 36,
    DYNAMIC_RELR_ENTRY = 37,
    DYNAMIC_GNU_RELA_COUNT = 0x6ffffff9,
    DYNAMIC_FLAGS_1 = 0x6ffffffb,
    DYNAMIC_FLAG_SYMBOLIC = 2,
    DYNAMIC_FLAG_BIND_NOW = 8,
    DYNAMIC_FLAG_1_NOW = 1,
    RELOCATION_X86_64_JUMP_SLOT = 7,
    RELOCATION_X86_64_RELATIVE = 8,
    SYMBOL_UNDEFINED = 0,
    SYMBOL_BIND_GLOBAL = 1,
    SYMBOL_FUNCTION = 2,
    SYMBOL_VISIBILITY_DEFAULT = 0,
    SHARED_PROFILE_CONSUMER = 1,
    SHARED_PROFILE_PROVIDER = 2,
    PAGE_SIZE = 4096,
    MAXIMUM_PROGRAM_HEADERS = 16,
    MAXIMUM_DYNAMIC_ENTRIES = 64,
    MAXIMUM_SHARED_LOADS = 8,
    MAXIMUM_SHARED_FILE_BYTES = 64 * 1024,
    MAXIMUM_DYNAMIC_SYMBOLS = 256,
};

static const uintptr_t consumer_object_base = UINT64_C(0x30000000);
static const uintptr_t provider_object_base = UINT64_C(0x31000000);
static const char expected_path[] = "/exec-target";
static const char expected_needed[] = "libarach-probe.so";
static const char expected_provider[] = "libarach-provider.so";
static const char expected_symbol[] = "arach_shared_probe";
static const char expected_provider_symbol[] = "arach_provider_value";
static const char enter_marker[] = "ARACH_C2_RUNTIME_LINKER_ENTER\n";
static const char needed_marker[] = "ARACH_C2_DT_NEEDED_PASS\n";
static const char graph_marker[] = "ARACH_C2_DEPENDENCY_GRAPH_PASS\n";
static const char relocation_marker[] = "ARACH_C2_SHARED_RELOCATION_PASS\n";
static const char external_marker[] = "ARACH_C2_EXTERNAL_SYMBOL_PASS\n";
static const char pass_marker[] = "ARACH_C2_RUNTIME_LINKER_PASS\n";
static const char stack_failure[] = "ARACH_C2_LINKER_STACK_FAIL\n";
static const char headers_failure[] = "ARACH_C2_LINKER_HEADERS_FAIL\n";
static const char base_failure[] = "ARACH_C2_LINKER_BASE_FAIL\n";
static const char pointers_failure[] = "ARACH_C2_LINKER_POINTERS_FAIL\n";
static const char path_failure[] = "ARACH_C2_LINKER_PATH_FAIL\n";
static const char random_failure[] = "ARACH_C2_LINKER_RANDOM_FAIL\n";
static const char dependency_failure[] = "ARACH_C2_LINKER_DEPENDENCY_FAIL\n";
static const char shared_open_failure[] = "ARACH_C2_LINKER_SHARED_OPEN_FAIL\n";
static const char shared_elf_failure[] = "ARACH_C2_LINKER_SHARED_ELF_FAIL\n";
static const char shared_map_failure[] = "ARACH_C2_LINKER_SHARED_MAP_FAIL\n";
static const char shared_dynamic_failure[] = "ARACH_C2_LINKER_SHARED_DYNAMIC_FAIL\n";
static const char shared_graph_failure[] = "ARACH_C2_LINKER_SHARED_GRAPH_FAIL\n";
static const char shared_relocation_failure[] =
    "ARACH_C2_LINKER_SHARED_RELOCATION_FAIL\n";
static const char shared_external_failure[] =
    "ARACH_C2_LINKER_SHARED_EXTERNAL_FAIL\n";
static const char shared_symbol_failure[] = "ARACH_C2_LINKER_SHARED_SYMBOL_FAIL\n";
static const char shared_call_failure[] = "ARACH_C2_LINKER_SHARED_CALL_FAIL\n";

typedef struct {
    uint8_t identity[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t program_header_offset;
    uint64_t section_header_offset;
    uint32_t flags;
    uint16_t header_size;
    uint16_t program_header_size;
    uint16_t program_header_count;
    uint16_t section_header_size;
    uint16_t section_header_count;
    uint16_t section_name_index;
} Elf64Header;

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t alignment;
} Elf64ProgramHeader;

typedef struct {
    int64_t tag;
    uint64_t value;
} Elf64Dynamic;

typedef struct {
    uint32_t name;
    uint8_t information;
    uint8_t other;
    uint16_t section_index;
    uint64_t value;
    uint64_t size;
} Elf64Symbol;

typedef struct {
    uint64_t offset;
    uint64_t information;
    int64_t addend;
} Elf64Rela;

typedef struct {
    uintptr_t address;
    size_t memory_size;
    size_t mapping_size;
    uint32_t flags;
} MappedLoad;

typedef struct {
    uintptr_t hash;
    uintptr_t string_table;
    uintptr_t symbol_table;
    uintptr_t relocations;
    uintptr_t jump_relocations;
    uintptr_t plt_got;
    size_t string_size;
    size_t relocation_size;
    size_t jump_relocation_size;
    size_t relocation_entry_size;
    size_t symbol_entry_size;
    size_t soname_offset;
    size_t needed_offset;
    size_t relative_count;
    uint64_t plt_relocation_type;
    uint64_t flags;
    uint64_t flags_1;
    int has_soname;
    int has_needed;
    int has_relative_count;
    int has_plt_relocation_type;
    int has_flags;
    int has_flags_1;
    int has_symbolic;
} SharedDynamic;

typedef struct {
    uintptr_t base;
    long descriptor;
    uintptr_t temporary;
    size_t temporary_size;
    const Elf64Header *header;
    const Elf64ProgramHeader *headers;
    MappedLoad loads[MAXIMUM_SHARED_LOADS];
    size_t load_count;
    SharedDynamic dynamic;
} LoadedObject;

_Static_assert(sizeof(Elf64Header) == 64, "ELF64 header layout");
_Static_assert(sizeof(Elf64ProgramHeader) == 56, "ELF64 program header layout");
_Static_assert(sizeof(Elf64Dynamic) == 16, "ELF64 dynamic entry layout");
_Static_assert(sizeof(Elf64Symbol) == 24, "ELF64 symbol layout");
_Static_assert(sizeof(Elf64Rela) == 24, "ELF64 relocation layout");

extern void _start(void);
uintptr_t arach_runtime_linker_start(const uintptr_t *stack);

static long syscall6(uint64_t number, uint64_t first, uint64_t second,
                     uint64_t third, uint64_t fourth, uint64_t fifth,
                     uint64_t sixth) {
    register uint64_t rax __asm__("rax") = number;
    register uint64_t rdi __asm__("rdi") = first;
    register uint64_t rsi __asm__("rsi") = second;
    register uint64_t rdx __asm__("rdx") = third;
    register uint64_t r10 __asm__("r10") = fourth;
    register uint64_t r8 __asm__("r8") = fifth;
    register uint64_t r9 __asm__("r9") = sixth;
    __asm__ volatile("syscall"
                     : "+a"(rax)
                     : "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10), "r"(r8),
                       "r"(r9)
                     : "rcx", "r11", "memory");
    return (long)rax;
}

static long syscall3(uint64_t number, uint64_t first, uint64_t second,
                     uint64_t third) {
    return syscall6(number, first, second, third, 0, 0, 0);
}

static int syscall_failed(long result) { return result < 0; }

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

static int write_marker(const char *marker, size_t length) {
    return syscall3(SYS_WRITE, 1, (uintptr_t)marker, length) == (long)length;
}

static int bytes_equal(const char *left, const char *right, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

static int bounded_string_equals(const char *value, size_t capacity,
                                 const char *expected,
                                 size_t expected_length) {
    return expected_length < capacity &&
           bytes_equal(value, expected, expected_length) &&
           value[expected_length] == '\0';
}

static int checked_add(uintptr_t base, uint64_t offset, uintptr_t *result) {
    if (offset > UINTPTR_MAX - base) {
        return 0;
    }
    *result = base + (uintptr_t)offset;
    return 1;
}

static int checked_range(uintptr_t start, size_t length, uintptr_t *end) {
    if (length > UINTPTR_MAX - start) {
        return 0;
    }
    *end = start + length;
    return 1;
}

static int round_to_pages(size_t length, size_t *rounded) {
    if (length == 0 || length > SIZE_MAX - (PAGE_SIZE - 1)) {
        return 0;
    }
    *rounded = (length + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);
    return 1;
}

static int main_range_contains(const Elf64ProgramHeader *headers,
                               size_t header_count, uintptr_t load_base,
                               uintptr_t address, size_t length) {
    uintptr_t requested_end = 0;
    if (!checked_range(address, length, &requested_end)) {
        return 0;
    }
    for (size_t index = 0; index < header_count; ++index) {
        if (headers[index].type != PROGRAM_LOAD) {
            continue;
        }
        uintptr_t start = 0;
        uintptr_t end = 0;
        if (!checked_add(load_base, headers[index].virtual_address, &start) ||
            headers[index].memory_size > SIZE_MAX ||
            !checked_range(start, (size_t)headers[index].memory_size, &end)) {
            return 0;
        }
        if (address >= start && requested_end <= end) {
            return 1;
        }
    }
    return 0;
}

static int discover_dependency(const Elf64ProgramHeader *headers,
                               size_t header_count, uintptr_t *main_base,
                               char *path, size_t path_capacity) {
    const Elf64ProgramHeader *header_table = NULL;
    const Elf64ProgramHeader *dynamic_program = NULL;
    for (size_t index = 0; index < header_count; ++index) {
        if (headers[index].type == PROGRAM_HEADERS) {
            if (header_table != NULL) {
                return 0;
            }
            header_table = &headers[index];
        } else if (headers[index].type == PROGRAM_DYNAMIC) {
            if (dynamic_program != NULL) {
                return 0;
            }
            dynamic_program = &headers[index];
        }
    }
    if (header_table == NULL || dynamic_program == NULL ||
        header_table->virtual_address > (uintptr_t)headers ||
        dynamic_program->memory_size < sizeof(Elf64Dynamic) ||
        dynamic_program->memory_size / sizeof(Elf64Dynamic) >
            MAXIMUM_DYNAMIC_ENTRIES) {
        return 0;
    }
    *main_base = (uintptr_t)headers - header_table->virtual_address;

    uintptr_t dynamic_address = 0;
    if (!checked_add(*main_base, dynamic_program->virtual_address,
                     &dynamic_address) ||
        !main_range_contains(headers, header_count, *main_base, dynamic_address,
                             (size_t)dynamic_program->memory_size)) {
        return 0;
    }
    const Elf64Dynamic *dynamic = (const Elf64Dynamic *)dynamic_address;
    size_t needed_offset = 0;
    size_t string_size = 0;
    uintptr_t string_table = 0;
    int has_needed = 0;
    int has_terminator = 0;
    size_t entries = (size_t)dynamic_program->memory_size / sizeof(*dynamic);
    for (size_t index = 0; index < entries; ++index) {
        switch (dynamic[index].tag) {
        case DYNAMIC_NULL:
            has_terminator = 1;
            index = entries;
            break;
        case DYNAMIC_NEEDED:
            if (has_needed || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            needed_offset = (size_t)dynamic[index].value;
            has_needed = 1;
            break;
        case DYNAMIC_STRING_TABLE:
            if (string_table != 0 ||
                !checked_add(*main_base, dynamic[index].value,
                             &string_table)) {
                return 0;
            }
            break;
        case DYNAMIC_STRING_SIZE:
            if (string_size != 0 || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            string_size = (size_t)dynamic[index].value;
            break;
        default:
            return 0;
        }
    }
    if (!has_terminator || !has_needed || string_table == 0 ||
        string_size == 0 || needed_offset >= string_size ||
        !main_range_contains(headers, header_count, *main_base, string_table,
                             string_size)) {
        return 0;
    }
    const char *needed = (const char *)(string_table + needed_offset);
    size_t available = string_size - needed_offset;
    if (!bounded_string_equals(needed, available, expected_needed,
                               sizeof(expected_needed) - 1) ||
        path_capacity < sizeof(expected_needed) + 1) {
        return 0;
    }
    path[0] = '/';
    for (size_t index = 0; index < sizeof(expected_needed); ++index) {
        path[index + 1] = needed[index];
    }
    return 1;
}

static int mapped_range_contains(const MappedLoad *loads, size_t load_count,
                                 uintptr_t address, size_t length,
                                 uint32_t required_flags) {
    uintptr_t requested_end = 0;
    if (!checked_range(address, length, &requested_end)) {
        return 0;
    }
    for (size_t index = 0; index < load_count; ++index) {
        uintptr_t load_end = 0;
        if (!checked_range(loads[index].address, loads[index].memory_size,
                           &load_end)) {
            return 0;
        }
        if (address >= loads[index].address && requested_end <= load_end &&
            (loads[index].flags & required_flags) == required_flags) {
            return 1;
        }
    }
    return 0;
}

static int mappings_overlap(const MappedLoad *loads, size_t load_count,
                            uintptr_t address, size_t length) {
    uintptr_t end = 0;
    if (!checked_range(address, length, &end)) {
        return 1;
    }
    for (size_t index = 0; index < load_count; ++index) {
        uintptr_t existing_end = 0;
        if (!checked_range(loads[index].address, loads[index].mapping_size,
                           &existing_end) ||
            (address < existing_end && loads[index].address < end)) {
            return 1;
        }
    }
    return 0;
}

static void zero_bytes(uint8_t *bytes, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

static int parse_shared_dynamic(LoadedObject *object, int profile,
                                const char *expected_soname,
                                size_t expected_soname_length) {
    const Elf64ProgramHeader *dynamic_program = NULL;
    for (size_t index = 0; index < object->header->program_header_count;
         ++index) {
        if (object->headers[index].type == PROGRAM_DYNAMIC) {
            if (dynamic_program != NULL) {
                return 0;
            }
            dynamic_program = &object->headers[index];
        }
    }
    if (dynamic_program == NULL ||
        dynamic_program->memory_size < sizeof(Elf64Dynamic) ||
        dynamic_program->memory_size % sizeof(Elf64Dynamic) != 0 ||
        dynamic_program->memory_size / sizeof(Elf64Dynamic) >
            MAXIMUM_DYNAMIC_ENTRIES) {
        return 0;
    }
    uintptr_t address = 0;
    if (!checked_add(object->base, dynamic_program->virtual_address, &address) ||
        !mapped_range_contains(object->loads, object->load_count, address,
                               (size_t)dynamic_program->memory_size, 0)) {
        return 0;
    }
    const Elf64Dynamic *dynamic = (const Elf64Dynamic *)address;
    size_t entries = (size_t)dynamic_program->memory_size / sizeof(*dynamic);
    int terminator = 0;
    SharedDynamic *result = &object->dynamic;
    result->hash = 0;
    result->string_table = 0;
    result->symbol_table = 0;
    result->relocations = 0;
    result->jump_relocations = 0;
    result->plt_got = 0;
    result->string_size = 0;
    result->relocation_size = 0;
    result->jump_relocation_size = 0;
    result->relocation_entry_size = 0;
    result->symbol_entry_size = 0;
    result->soname_offset = 0;
    result->needed_offset = 0;
    result->relative_count = 0;
    result->plt_relocation_type = 0;
    result->flags = 0;
    result->flags_1 = 0;
    result->has_soname = 0;
    result->has_needed = 0;
    result->has_relative_count = 0;
    result->has_plt_relocation_type = 0;
    result->has_flags = 0;
    result->has_flags_1 = 0;
    result->has_symbolic = 0;
    for (size_t index = 0; index < entries; ++index) {
        uintptr_t pointer = 0;
        switch (dynamic[index].tag) {
        case DYNAMIC_NULL:
            terminator = 1;
            index = entries;
            break;
        case DYNAMIC_HASH:
            if (result->hash != 0 ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->hash = pointer;
            break;
        case DYNAMIC_STRING_TABLE:
            if (result->string_table != 0 ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->string_table = pointer;
            break;
        case DYNAMIC_SYMBOL_TABLE:
            if (result->symbol_table != 0 ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->symbol_table = pointer;
            break;
        case DYNAMIC_RELA:
            if (result->relocations != 0 ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->relocations = pointer;
            break;
        case DYNAMIC_NEEDED:
            if (result->has_needed || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->needed_offset = (size_t)dynamic[index].value;
            result->has_needed = 1;
            break;
        case DYNAMIC_PLT_RELOCATION_SIZE:
            if (result->jump_relocation_size != 0 ||
                dynamic[index].value == 0 || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->jump_relocation_size = (size_t)dynamic[index].value;
            break;
        case DYNAMIC_PLT_GOT:
            if (result->plt_got != 0 ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->plt_got = pointer;
            break;
        case DYNAMIC_STRING_SIZE:
            if (result->string_size != 0 || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->string_size = (size_t)dynamic[index].value;
            break;
        case DYNAMIC_RELA_SIZE:
            if (result->relocation_size != 0 ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->relocation_size = (size_t)dynamic[index].value;
            break;
        case DYNAMIC_RELA_ENTRY:
            if (result->relocation_entry_size != 0 ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->relocation_entry_size = (size_t)dynamic[index].value;
            break;
        case DYNAMIC_SYMBOL_ENTRY:
            if (result->symbol_entry_size != 0 ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->symbol_entry_size = (size_t)dynamic[index].value;
            break;
        case DYNAMIC_SONAME:
            if (result->has_soname || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->soname_offset = (size_t)dynamic[index].value;
            result->has_soname = 1;
            break;
        case DYNAMIC_SYMBOLIC:
            if (result->has_symbolic || dynamic[index].value != 0) {
                return 0;
            }
            result->has_symbolic = 1;
            break;
        case DYNAMIC_FLAGS:
            if (result->has_flags) {
                return 0;
            }
            result->flags = dynamic[index].value;
            result->has_flags = 1;
            break;
        case DYNAMIC_GNU_RELA_COUNT:
            if (result->has_relative_count ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->relative_count = (size_t)dynamic[index].value;
            result->has_relative_count = 1;
            break;
        case DYNAMIC_PLT_RELOCATION_TYPE:
            if (result->has_plt_relocation_type) {
                return 0;
            }
            result->plt_relocation_type = dynamic[index].value;
            result->has_plt_relocation_type = 1;
            break;
        case DYNAMIC_JUMP_RELOCATION:
            if (result->jump_relocations != 0 ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->jump_relocations = pointer;
            break;
        case DYNAMIC_FLAGS_1:
            if (result->has_flags_1) {
                return 0;
            }
            result->flags_1 = dynamic[index].value;
            result->has_flags_1 = 1;
            break;
        case DYNAMIC_INIT:
        case DYNAMIC_FINI:
        case DYNAMIC_REL:
        case DYNAMIC_REL_SIZE:
        case DYNAMIC_REL_ENTRY:
        case DYNAMIC_DEBUG:
        case DYNAMIC_TEXT_RELOCATION:
        case DYNAMIC_BIND_NOW:
        case DYNAMIC_INIT_ARRAY:
        case DYNAMIC_FINI_ARRAY:
        case DYNAMIC_INIT_ARRAY_SIZE:
        case DYNAMIC_FINI_ARRAY_SIZE:
        case DYNAMIC_RUNPATH:
        case DYNAMIC_PREINIT_ARRAY:
        case DYNAMIC_PREINIT_ARRAY_SIZE:
        case DYNAMIC_RELR_SIZE:
        case DYNAMIC_RELR:
        case DYNAMIC_RELR_ENTRY:
            return 0;
        default:
            return 0;
        }
    }
    if (!terminator || result->hash == 0 || result->string_table == 0 ||
        result->symbol_table == 0 || result->string_size == 0 ||
        result->symbol_entry_size != sizeof(Elf64Symbol) ||
        !result->has_soname || !result->has_flags ||
        result->soname_offset >= result->string_size ||
        !mapped_range_contains(object->loads, object->load_count, result->hash,
                               2 * sizeof(uint32_t), 0) ||
        !mapped_range_contains(object->loads, object->load_count,
                               result->string_table, result->string_size, 0) ||
        !bounded_string_equals(
            (const char *)(result->string_table + result->soname_offset),
            result->string_size - result->soname_offset, expected_soname,
            expected_soname_length)) {
        return 0;
    }
    if (profile == SHARED_PROFILE_CONSUMER) {
        return result->has_needed &&
               result->needed_offset < result->string_size &&
               bounded_string_equals(
                   (const char *)(result->string_table +
                                  result->needed_offset),
                   result->string_size - result->needed_offset,
                   expected_provider, sizeof(expected_provider) - 1) &&
               result->relocations == 0 && result->relocation_size == 0 &&
               result->relocation_entry_size == 0 &&
               !result->has_relative_count &&
               result->jump_relocations != 0 &&
               result->jump_relocation_size == sizeof(Elf64Rela) &&
               result->plt_got != 0 && result->has_plt_relocation_type &&
               result->plt_relocation_type == DYNAMIC_RELA &&
               result->flags ==
                   (DYNAMIC_FLAG_SYMBOLIC | DYNAMIC_FLAG_BIND_NOW) &&
               result->has_flags_1 &&
               result->flags_1 == DYNAMIC_FLAG_1_NOW &&
               mapped_range_contains(object->loads, object->load_count,
                                     result->jump_relocations,
                                     result->jump_relocation_size, 0) &&
               mapped_range_contains(object->loads, object->load_count,
                                     result->plt_got,
                                     4 * sizeof(uintptr_t),
                                     PROGRAM_WRITABLE);
    }
    if (profile == SHARED_PROFILE_PROVIDER) {
        return !result->has_needed && result->jump_relocations == 0 &&
               result->jump_relocation_size == 0 && result->plt_got == 0 &&
               !result->has_plt_relocation_type && result->relocations != 0 &&
               result->relocation_size == sizeof(Elf64Rela) &&
               result->relocation_entry_size == sizeof(Elf64Rela) &&
               result->has_relative_count && result->relative_count == 1 &&
               result->flags == DYNAMIC_FLAG_SYMBOLIC &&
               !result->has_flags_1 &&
               mapped_range_contains(object->loads, object->load_count,
                                     result->relocations,
                                     result->relocation_size, 0);
    }
    return 0;
}

static int build_shared_dependency_path(const LoadedObject *consumer,
                                        char *path, size_t path_capacity) {
    const SharedDynamic *dynamic = &consumer->dynamic;
    if (!dynamic->has_needed || dynamic->needed_offset >= dynamic->string_size ||
        path_capacity < sizeof(expected_provider) + 1) {
        return 0;
    }
    const char *needed =
        (const char *)(dynamic->string_table + dynamic->needed_offset);
    size_t available = dynamic->string_size - dynamic->needed_offset;
    if (!bounded_string_equals(needed, available, expected_provider,
                               sizeof(expected_provider) - 1)) {
        return 0;
    }
    path[0] = '/';
    for (size_t index = 0; index < sizeof(expected_provider); ++index) {
        path[index + 1] = needed[index];
    }
    return 1;
}

static int dynamic_symbol_count(const LoadedObject *object,
                                uint32_t *symbol_count) {
    const uint32_t *hash = (const uint32_t *)object->dynamic.hash;
    uint32_t bucket_count = hash[0];
    uint32_t chain_count = hash[1];
    if (bucket_count == 0 || bucket_count > MAXIMUM_DYNAMIC_SYMBOLS ||
        chain_count == 0 || chain_count > MAXIMUM_DYNAMIC_SYMBOLS) {
        return 0;
    }
    size_t hash_words = 2 + (size_t)bucket_count + (size_t)chain_count;
    if (!mapped_range_contains(object->loads, object->load_count,
                               object->dynamic.hash,
                               hash_words * sizeof(uint32_t), 0) ||
        !mapped_range_contains(object->loads, object->load_count,
                               object->dynamic.symbol_table,
                               (size_t)chain_count * sizeof(Elf64Symbol), 0)) {
        return 0;
    }
    *symbol_count = chain_count;
    return 1;
}

static int apply_relative_relocations(const LoadedObject *object) {
    const Elf64Rela *relocations =
        (const Elf64Rela *)object->dynamic.relocations;
    size_t count = object->dynamic.relocation_size / sizeof(*relocations);
    if (count == 0 || count > MAXIMUM_DYNAMIC_ENTRIES) {
        return 0;
    }
    for (size_t index = 0; index < count; ++index) {
        uint32_t relocation_type = (uint32_t)relocations[index].information;
        uint32_t symbol = (uint32_t)(relocations[index].information >> 32);
        uintptr_t target = 0;
        uintptr_t value = 0;
        if (relocation_type != RELOCATION_X86_64_RELATIVE || symbol != 0 ||
            relocations[index].addend < 0 ||
            !checked_add(object->base, relocations[index].offset, &target) ||
            !checked_add(object->base,
                         (uint64_t)relocations[index].addend, &value) ||
            target % sizeof(uintptr_t) != 0 ||
            !mapped_range_contains(object->loads, object->load_count, target,
                                   sizeof(uintptr_t), PROGRAM_WRITABLE) ||
            !mapped_range_contains(object->loads, object->load_count, value, 1,
                                   0)) {
            return 0;
        }
        *(volatile uintptr_t *)target = value;
        if (*(volatile const uintptr_t *)target != value) {
            return 0;
        }
    }
    return 1;
}

static int find_exported_symbol(const LoadedObject *object,
                                const char *expected_name,
                                size_t expected_name_length,
                                uintptr_t *symbol_address) {
    uint32_t symbol_count = 0;
    if (!dynamic_symbol_count(object, &symbol_count)) {
        return 0;
    }
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)object->dynamic.symbol_table;
    for (uint32_t index = 0; index < symbol_count; ++index) {
        if (symbols[index].name >= object->dynamic.string_size ||
            symbols[index].section_index == SYMBOL_UNDEFINED ||
            (symbols[index].information & 0x0f) != SYMBOL_FUNCTION ||
            (symbols[index].information >> 4) != SYMBOL_BIND_GLOBAL ||
            (symbols[index].other & 0x03) != SYMBOL_VISIBILITY_DEFAULT ||
            symbols[index].size == 0 || symbols[index].size > SIZE_MAX) {
            continue;
        }
        const char *name = (const char *)(object->dynamic.string_table +
                                         symbols[index].name);
        size_t available =
            object->dynamic.string_size - symbols[index].name;
        uintptr_t address = 0;
        if (bounded_string_equals(name, available, expected_name,
                                  expected_name_length) &&
            checked_add(object->base, symbols[index].value, &address) &&
            mapped_range_contains(object->loads, object->load_count, address,
                                  (size_t)symbols[index].size,
                                  PROGRAM_EXECUTABLE)) {
            *symbol_address = address;
            return 1;
        }
    }
    return 0;
}

static int apply_external_relocation(const LoadedObject *consumer,
                                     const LoadedObject *provider) {
    const Elf64Rela *relocation =
        (const Elf64Rela *)consumer->dynamic.jump_relocations;
    uint32_t relocation_type = (uint32_t)relocation->information;
    uint32_t symbol_index = (uint32_t)(relocation->information >> 32);
    uint32_t consumer_symbol_count = 0;
    uintptr_t target = 0;
    uintptr_t expected_target = 0;
    if (!dynamic_symbol_count(consumer, &consumer_symbol_count) ||
        relocation_type != RELOCATION_X86_64_JUMP_SLOT || symbol_index == 0 ||
        symbol_index >= consumer_symbol_count || relocation->addend != 0 ||
        !checked_add(consumer->base, relocation->offset, &target) ||
        !checked_add(consumer->dynamic.plt_got, 3 * sizeof(uintptr_t),
                     &expected_target) ||
        target != expected_target || target % sizeof(uintptr_t) != 0 ||
        !mapped_range_contains(consumer->loads, consumer->load_count, target,
                               sizeof(uintptr_t), PROGRAM_WRITABLE)) {
        return 0;
    }
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)consumer->dynamic.symbol_table;
    const Elf64Symbol *symbol = &symbols[symbol_index];
    if (symbol->name >= consumer->dynamic.string_size ||
        symbol->section_index != SYMBOL_UNDEFINED ||
        (symbol->information & 0x0f) != SYMBOL_FUNCTION ||
        (symbol->information >> 4) != SYMBOL_BIND_GLOBAL ||
        (symbol->other & 0x03) != SYMBOL_VISIBILITY_DEFAULT) {
        return 0;
    }
    const char *name =
        (const char *)(consumer->dynamic.string_table + symbol->name);
    size_t available = consumer->dynamic.string_size - symbol->name;
    uintptr_t provider_symbol = 0;
    if (!bounded_string_equals(name, available, expected_provider_symbol,
                               sizeof(expected_provider_symbol) - 1) ||
        !find_exported_symbol(provider, expected_provider_symbol,
                              sizeof(expected_provider_symbol) - 1,
                              &provider_symbol)) {
        return 0;
    }
    *(volatile uintptr_t *)target = provider_symbol;
    return *(volatile const uintptr_t *)target == provider_symbol;
}

static int seal_shared_loads(const LoadedObject *object) {
    for (size_t index = 0; index < object->load_count; ++index) {
        uint64_t protection = PROT_READ;
        if ((object->loads[index].flags & PROGRAM_READABLE) == 0 ||
            ((object->loads[index].flags & PROGRAM_WRITABLE) != 0 &&
             (object->loads[index].flags & PROGRAM_EXECUTABLE) != 0)) {
            return 0;
        }
        if ((object->loads[index].flags & PROGRAM_WRITABLE) != 0) {
            protection |= PROT_WRITE;
        }
        if ((object->loads[index].flags & PROGRAM_EXECUTABLE) != 0) {
            protection |= PROT_EXEC;
        }
        if (syscall3(SYS_MPROTECT, object->loads[index].address,
                     object->loads[index].mapping_size, protection) != 0) {
            return 0;
        }
    }
    return 1;
}

static int release_shared_snapshot(const LoadedObject *object) {
    return syscall3(SYS_CLOSE, (uint64_t)object->descriptor, 0, 0) == 0 &&
           syscall3(SYS_MUNMAP, object->temporary, object->temporary_size, 0) ==
               0;
}

static void load_shared_object(const char *path, uintptr_t base, int profile,
                               const char *expected_soname,
                               size_t expected_soname_length,
                               LoadedObject *object) {
    long descriptor = syscall3(SYS_OPEN, (uintptr_t)path, O_RDONLY, 0);
    if (descriptor < 3) {
        fail_with(shared_open_failure, sizeof(shared_open_failure) - 1);
    }
    long file_size = syscall3(SYS_LSEEK, (uint64_t)descriptor, 0, SEEK_END);
    if (file_size < (long)sizeof(Elf64Header) ||
        file_size > MAXIMUM_SHARED_FILE_BYTES ||
        syscall3(SYS_LSEEK, (uint64_t)descriptor, 0, SEEK_SET) != 0) {
        fail_with(shared_open_failure, sizeof(shared_open_failure) - 1);
    }
    size_t temporary_size = 0;
    if (!round_to_pages((size_t)file_size, &temporary_size)) {
        fail_with(shared_elf_failure, sizeof(shared_elf_failure) - 1);
    }
    long temporary_result =
        syscall6(SYS_MMAP, 0, (uint64_t)file_size, PROT_READ, MAP_PRIVATE,
                 (uint64_t)descriptor, 0);
    if (syscall_failed(temporary_result)) {
        fail_with(shared_map_failure, sizeof(shared_map_failure) - 1);
    }
    uintptr_t temporary = (uintptr_t)temporary_result;
    const Elf64Header *header = (const Elf64Header *)temporary;
    if (header->identity[0] != 0x7f || header->identity[1] != 'E' ||
        header->identity[2] != 'L' || header->identity[3] != 'F' ||
        header->identity[4] != ELF_CLASS_64 ||
        header->identity[5] != ELF_DATA_LITTLE_ENDIAN ||
        header->identity[6] != ELF_VERSION_CURRENT ||
        header->type != ELF_TYPE_SHARED_OBJECT ||
        header->machine != ELF_MACHINE_X86_64 ||
        header->version != ELF_VERSION_CURRENT ||
        header->entry != 0 ||
        header->header_size != sizeof(Elf64Header) ||
        header->program_header_size != sizeof(Elf64ProgramHeader) ||
        header->program_header_count == 0 ||
        header->program_header_count > MAXIMUM_PROGRAM_HEADERS ||
        header->program_header_offset > (uint64_t)file_size ||
        (uint64_t)header->program_header_count * sizeof(Elf64ProgramHeader) >
            (uint64_t)file_size - header->program_header_offset) {
        fail_with(shared_elf_failure, sizeof(shared_elf_failure) - 1);
    }
    const Elf64ProgramHeader *headers = (const Elf64ProgramHeader *)(
        temporary + (uintptr_t)header->program_header_offset);
    object->base = base;
    object->descriptor = descriptor;
    object->temporary = temporary;
    object->temporary_size = temporary_size;
    object->header = header;
    object->headers = headers;
    object->load_count = 0;
    size_t load_count = 0;
    for (size_t index = 0; index < header->program_header_count; ++index) {
        const Elf64ProgramHeader *program = &headers[index];
        if (program->type != PROGRAM_LOAD) {
            if (program->type != PROGRAM_DYNAMIC) {
                fail_with(shared_elf_failure,
                          sizeof(shared_elf_failure) - 1);
            }
            continue;
        }
        if (load_count == MAXIMUM_SHARED_LOADS || program->memory_size == 0 ||
            program->file_size == 0 ||
            program->file_size > program->memory_size ||
            program->memory_size > SIZE_MAX || program->file_size > SIZE_MAX ||
            program->offset % PAGE_SIZE != 0 ||
            program->virtual_address % PAGE_SIZE != 0 ||
            program->alignment != PAGE_SIZE ||
            program->offset > (uint64_t)file_size ||
            program->file_size > (uint64_t)file_size - program->offset ||
            (program->flags &
             ~(uint32_t)(PROGRAM_READABLE | PROGRAM_WRITABLE |
                         PROGRAM_EXECUTABLE)) !=
                0 ||
            (program->flags & PROGRAM_READABLE) == 0 ||
            ((program->flags & PROGRAM_WRITABLE) != 0 &&
             (program->flags & PROGRAM_EXECUTABLE) != 0)) {
            fail_with(shared_elf_failure, sizeof(shared_elf_failure) - 1);
        }
        size_t mapping_size = 0;
        size_t available_file_span = 0;
        if (!round_to_pages((size_t)program->memory_size, &mapping_size) ||
            !round_to_pages((size_t)file_size - (size_t)program->offset,
                            &available_file_span) ||
            mapping_size > available_file_span) {
            fail_with(shared_elf_failure, sizeof(shared_elf_failure) - 1);
        }
        uintptr_t address = 0;
        uintptr_t mapping_end = 0;
        uintptr_t object_end = 0;
        if (!checked_add(base, program->virtual_address, &address) ||
            !checked_range(address, mapping_size, &mapping_end) ||
            !checked_add(base, MAXIMUM_SHARED_FILE_BYTES, &object_end) ||
            address < base || mapping_end > object_end ||
            mappings_overlap(object->loads, load_count, address,
                             mapping_size)) {
            fail_with(shared_map_failure, sizeof(shared_map_failure) - 1);
        }
        long mapped = syscall6(SYS_MMAP, address, mapping_size,
                               PROT_READ | PROT_WRITE, MAP_PRIVATE,
                               (uint64_t)descriptor, program->offset);
        if (mapped != (long)address) {
            fail_with(shared_map_failure, sizeof(shared_map_failure) - 1);
        }
        zero_bytes((uint8_t *)(address + (size_t)program->file_size),
                   mapping_size - (size_t)program->file_size);
        object->loads[load_count].address = address;
        object->loads[load_count].memory_size =
            (size_t)program->memory_size;
        object->loads[load_count].mapping_size = mapping_size;
        object->loads[load_count].flags = program->flags;
        ++load_count;
    }
    if (load_count == 0) {
        fail_with(shared_elf_failure, sizeof(shared_elf_failure) - 1);
    }
    object->load_count = load_count;
    if (!parse_shared_dynamic(object, profile, expected_soname,
                              expected_soname_length)) {
        fail_with(shared_dynamic_failure,
                  sizeof(shared_dynamic_failure) - 1);
    }
}

uintptr_t arach_runtime_linker_start(const uintptr_t *stack) {
    if (!write_marker(enter_marker, sizeof(enter_marker) - 1)) {
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
    if (!found_terminator || program_headers == 0 ||
        program_header_size != sizeof(Elf64ProgramHeader) ||
        program_header_count < 4 ||
        program_header_count > MAXIMUM_PROGRAM_HEADERS ||
        page_size != PAGE_SIZE) {
        fail_with(headers_failure, sizeof(headers_failure) - 1);
    }
    if (runtime_linker_base == 0 || own_entry < runtime_linker_base ||
        own_entry >= runtime_linker_base + (64 * 1024)) {
        fail_with(base_failure, sizeof(base_failure) - 1);
    }
    if (executable_entry == 0 || random_address == 0 ||
        executable_path == 0) {
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
    if (aggregate == 0) {
        fail_with(random_failure, sizeof(random_failure) - 1);
    }

    char dependency_path[sizeof(expected_needed) + 1];
    uintptr_t main_base = 0;
    if (!discover_dependency((const Elf64ProgramHeader *)program_headers,
                             program_header_count, &main_base,
                             dependency_path, sizeof(dependency_path)) ||
        main_base == 0 ||
        !write_marker(needed_marker, sizeof(needed_marker) - 1)) {
        fail_with(dependency_failure, sizeof(dependency_failure) - 1);
    }
    LoadedObject consumer;
    load_shared_object(dependency_path, consumer_object_base,
                       SHARED_PROFILE_CONSUMER, expected_needed,
                       sizeof(expected_needed) - 1, &consumer);
    char provider_path[sizeof(expected_provider) + 1];
    if (!build_shared_dependency_path(&consumer, provider_path,
                                      sizeof(provider_path))) {
        fail_with(shared_graph_failure, sizeof(shared_graph_failure) - 1);
    }
    LoadedObject provider;
    load_shared_object(provider_path, provider_object_base,
                       SHARED_PROFILE_PROVIDER, expected_provider,
                       sizeof(expected_provider) - 1, &provider);
    if (!write_marker(graph_marker, sizeof(graph_marker) - 1)) {
        fail_with(shared_graph_failure, sizeof(shared_graph_failure) - 1);
    }
    if (!apply_relative_relocations(&provider) ||
        !write_marker(relocation_marker, sizeof(relocation_marker) - 1)) {
        fail_with(shared_relocation_failure,
                  sizeof(shared_relocation_failure) - 1);
    }
    if (!apply_external_relocation(&consumer, &provider)) {
        fail_with(shared_external_failure,
                  sizeof(shared_external_failure) - 1);
    }
    uintptr_t shared_symbol = 0;
    if (!find_exported_symbol(&consumer, expected_symbol,
                              sizeof(expected_symbol) - 1,
                              &shared_symbol)) {
        fail_with(shared_symbol_failure, sizeof(shared_symbol_failure) - 1);
    }
    if (!seal_shared_loads(&provider) || !seal_shared_loads(&consumer) ||
        !release_shared_snapshot(&provider) ||
        !release_shared_snapshot(&consumer)) {
        fail_with(shared_map_failure, sizeof(shared_map_failure) - 1);
    }
    typedef uint64_t (*SharedProbe)(uint64_t);
    SharedProbe shared_probe = (SharedProbe)shared_symbol;
    const uint64_t input = UINT64_C(0x1122334455667788);
    const uint64_t expected =
        (input + UINT64_C(0x1020304050607080)) ^
        UINT64_C(0xa5a55a5af0f00f0f);
    if (shared_probe(input) != expected ||
        !write_marker(external_marker, sizeof(external_marker) - 1)) {
        fail_with(shared_call_failure, sizeof(shared_call_failure) - 1);
    }
    if (!write_marker(pass_marker, sizeof(pass_marker) - 1)) {
        fail();
    }
    return executable_entry;
}
