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
    SYS_ARCH_PRCTL = 158,
    SYS_EXIT_GROUP = 231,
    O_RDONLY = 0,
    SEEK_SET = 0,
    SEEK_END = 2,
    PROT_READ = 1,
    PROT_WRITE = 2,
    PROT_EXEC = 4,
    MAP_PRIVATE = 2,
    MAP_ANONYMOUS = 32,
    ARCH_SET_FS = 0x1002,
    ELF_CLASS_64 = 2,
    ELF_DATA_LITTLE_ENDIAN = 1,
    ELF_VERSION_CURRENT = 1,
    ELF_TYPE_SHARED_OBJECT = 3,
    ELF_MACHINE_X86_64 = 62,
    PROGRAM_LOAD = 1,
    PROGRAM_DYNAMIC = 2,
    PROGRAM_HEADERS = 6,
    PROGRAM_TLS = 7,
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
    DYNAMIC_RPATH = 15,
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
    DYNAMIC_VERSION_SYMBOL = 0x6ffffff0,
    DYNAMIC_GNU_RELA_COUNT = 0x6ffffff9,
    DYNAMIC_FLAGS_1 = 0x6ffffffb,
    DYNAMIC_VERSION_DEFINITION = 0x6ffffffc,
    DYNAMIC_VERSION_DEFINITION_COUNT = 0x6ffffffd,
    DYNAMIC_VERSION_REQUIREMENT = 0x6ffffffe,
    DYNAMIC_VERSION_REQUIREMENT_COUNT = 0x6fffffff,
    DYNAMIC_FLAG_SYMBOLIC = 2,
    DYNAMIC_FLAG_BIND_NOW = 8,
    DYNAMIC_FLAG_STATIC_TLS = 16,
    DYNAMIC_FLAG_1_NOW = 1,
    RELOCATION_X86_64_JUMP_SLOT = 7,
    RELOCATION_X86_64_RELATIVE = 8,
    RELOCATION_X86_64_DTPMOD64 = 16,
    RELOCATION_X86_64_DTPOFF64 = 17,
    RELOCATION_X86_64_TPOFF64 = 18,
    SYMBOL_UNDEFINED = 0,
    SYMBOL_BIND_GLOBAL = 1,
    SYMBOL_NO_TYPE = 0,
    SYMBOL_OBJECT = 1,
    SYMBOL_FUNCTION = 2,
    SYMBOL_TLS = 6,
    SYMBOL_ABSOLUTE = 0xfff1,
    SYMBOL_VISIBILITY_DEFAULT = 0,
    VERSION_CURRENT = 1,
    VERSION_FLAG_BASE = 1,
    VERSION_INDEX_LOCAL = 0,
    VERSION_INDEX_GLOBAL = 1,
    VERSION_INDEX_HIDDEN = 0x8000,
    VERSION_INDEX_MASK = 0x7fff,
    PAGE_SIZE = 4096,
    MAXIMUM_PROGRAM_HEADERS = 16,
    MAXIMUM_DYNAMIC_ENTRIES = 64,
    MAXIMUM_SHARED_LOADS = 8,
    MAXIMUM_SHARED_FILE_BYTES = 64 * 1024,
    MAXIMUM_DYNAMIC_SYMBOLS = 256,
    MAXIMUM_LOADED_OBJECTS = 8,
    MAXIMUM_NEEDED_ENTRIES = 8,
    MAXIMUM_OBJECT_NAME_BYTES = 63,
    MAXIMUM_OBJECT_PATH_BYTES = 255,
    MAXIMUM_RUNPATH_DIRECTORIES = 4,
    MAXIMUM_RUNPATH_DIRECTORY_BYTES = 63,
    MAXIMUM_RUNPATH_STRING_BYTES = 255,
    MAXIMUM_SYMBOL_NAME_BYTES = 127,
    MAXIMUM_RELOCATIONS = 64,
    MAXIMUM_INITIALIZERS = 16,
    MAXIMUM_VERSION_DEFINITIONS = 16,
    MAXIMUM_VERSION_REQUIREMENTS = 16,
    MAXIMUM_VERSION_AUXILIARIES = 32,
    MAXIMUM_TLS_ALIGNMENT = PAGE_SIZE,
    MAXIMUM_STATIC_TLS_BYTES = 16 * 1024,
    ERROR_NO_ENTRY = -2,
};

static const uintptr_t first_object_base = UINT64_C(0x30000000);
static const uintptr_t object_address_stride = UINT64_C(0x01000000);
static const char expected_path[] = "/exec-target";
static const char expected_needed[] = "libarach-probe.so";
static const char expected_provider[] = "libarach-provider.so";
static const char expected_observer[] = "libarach-observer.so";
static const char expected_core[] = "libarach-core.so";
static const char expected_runpath[] = "/runpath";
static const char expected_root_object_path[] = "/libarach-probe.so";
static const char expected_provider_path[] =
    "/runpath/libarach-provider.so";
static const char expected_observer_path[] =
    "/runpath/libarach-observer.so";
static const char expected_core_path[] = "/runpath/libarach-core.so";
static const char expected_symbol[] = "arach_shared_probe";
static const char tls_resolver_symbol[] = "__tls_get_addr";
static const char enter_marker[] = "ARACH_C2_RUNTIME_LINKER_ENTER\n";
static const char needed_marker[] = "ARACH_C2_DT_NEEDED_PASS\n";
static const char graph_marker[] = "ARACH_C2_DEPENDENCY_GRAPH_PASS\n";
static const char multi_object_marker[] =
    "ARACH_C2_MULTI_OBJECT_GRAPH_PASS\n";
static const char relocation_marker[] = "ARACH_C2_SHARED_RELOCATION_PASS\n";
static const char symbol_scope_marker[] =
    "ARACH_C2_GLOBAL_SYMBOL_SCOPE_PASS\n";
static const char version_marker[] = "ARACH_C2_SYMBOL_VERSION_PASS\n";
static const char static_tls_marker[] = "ARACH_C2_STATIC_TLS_PASS\n";
static const char dynamic_tls_marker[] = "ARACH_C2_DYNAMIC_TLS_PASS\n";
static const char runpath_marker[] = "ARACH_C2_RUNPATH_PASS\n";
static const char initializer_marker[] =
    "ARACH_C2_INITIALIZER_ORDER_PASS\n";
static const char finalization_marker[] = "ARACH_C2_FINALIZATION_PASS\n";
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
static const char shared_tls_failure[] = "ARACH_C2_LINKER_STATIC_TLS_FAIL\n";
static const char shared_dynamic_tls_failure[] =
    "ARACH_C2_LINKER_DYNAMIC_TLS_FAIL\n";
static const char shared_runpath_failure[] =
    "ARACH_C2_LINKER_RUNPATH_FAIL\n";
static const char shared_version_failure[] =
    "ARACH_C2_LINKER_SYMBOL_VERSION_FAIL\n";
static const char shared_initializer_failure[] =
    "ARACH_C2_LINKER_INITIALIZER_FAIL\n";
static const char shared_finalization_failure[] =
    "ARACH_C2_LINKER_FINALIZATION_FAIL\n";
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
    uint16_t version;
    uint16_t flags;
    uint16_t index;
    uint16_t auxiliary_count;
    uint32_t hash;
    uint32_t auxiliary;
    uint32_t next;
} Elf64VersionDefinition;

typedef struct {
    uint32_t name;
    uint32_t next;
} Elf64VersionDefinitionAuxiliary;

typedef struct {
    uint16_t version;
    uint16_t auxiliary_count;
    uint32_t file;
    uint32_t auxiliary;
    uint32_t next;
} Elf64VersionRequirement;

typedef struct {
    uint32_t hash;
    uint16_t flags;
    uint16_t other;
    uint32_t name;
    uint32_t next;
} Elf64VersionRequirementAuxiliary;

typedef struct {
    uintptr_t address;
    size_t memory_size;
    size_t mapping_size;
    uint32_t flags;
} MappedLoad;

typedef struct {
    char bytes[MAXIMUM_OBJECT_NAME_BYTES + 1];
    size_t length;
} ObjectName;

typedef struct {
    char bytes[MAXIMUM_RUNPATH_DIRECTORY_BYTES + 1];
    size_t length;
} SearchDirectory;

typedef struct {
    SearchDirectory directories[MAXIMUM_RUNPATH_DIRECTORIES];
    size_t count;
} SearchPath;

typedef struct {
    ObjectName names[MAXIMUM_NEEDED_ENTRIES];
    size_t count;
} DependencyNames;

typedef struct {
    uintptr_t hash;
    uintptr_t string_table;
    uintptr_t symbol_table;
    uintptr_t relocations;
    uintptr_t jump_relocations;
    uintptr_t plt_got;
    uintptr_t init_function;
    uintptr_t init_array;
    uintptr_t fini_function;
    uintptr_t fini_array;
    uintptr_t version_symbols;
    uintptr_t version_definitions;
    uintptr_t version_requirements;
    size_t string_size;
    size_t relocation_size;
    size_t jump_relocation_size;
    size_t relocation_entry_size;
    size_t symbol_entry_size;
    size_t init_array_size;
    size_t fini_array_size;
    size_t version_definition_count;
    size_t version_requirement_count;
    size_t soname_offset;
    size_t runpath_offset;
    size_t needed_offsets[MAXIMUM_NEEDED_ENTRIES];
    size_t needed_count;
    size_t relative_count;
    uint64_t plt_relocation_type;
    uint64_t flags;
    uint64_t flags_1;
    int has_soname;
    int has_runpath;
    int has_relative_count;
    int has_plt_relocation_type;
    int has_flags;
    int has_flags_1;
    int has_symbolic;
    int has_bind_now;
    int has_init_function;
    int has_init_array;
    int has_init_array_size;
    int has_fini_function;
    int has_fini_array;
    int has_fini_array_size;
    int has_version_symbols;
    int has_version_definitions;
    int has_version_definition_count;
    int has_version_requirements;
    int has_version_requirement_count;
    SearchPath runpath;
} SharedDynamic;

typedef struct {
    ObjectName name;
    char path[MAXIMUM_OBJECT_PATH_BYTES + 1];
    size_t path_length;
    int loaded_from_runpath;
    uintptr_t base;
    long descriptor;
    uintptr_t temporary;
    size_t temporary_size;
    const Elf64Header *header;
    const Elf64ProgramHeader *headers;
    const Elf64ProgramHeader *tls_program;
    MappedLoad loads[MAXIMUM_SHARED_LOADS];
    size_t load_count;
    SharedDynamic dynamic;
    size_t dependencies[MAXIMUM_NEEDED_ENTRIES];
    size_t dependency_count;
    uintptr_t tls_instance;
    size_t tls_offset;
    size_t tls_module_id;
} LoadedObject;

typedef struct {
    LoadedObject objects[MAXIMUM_LOADED_OBJECTS];
    size_t object_count;
    size_t relocation_order[MAXIMUM_LOADED_OBJECTS];
    size_t relocation_count;
} ObjectGraph;

typedef struct {
    size_t relative;
    size_t external;
    size_t tls;
    size_t versioned;
} RelocationEvidence;

typedef struct {
    uintptr_t address;
    size_t size;
} DynamicTlsEntry;

typedef struct {
    size_t module;
    size_t offset;
} DynamicTlsIndex;

typedef struct {
    uintptr_t mapping;
    size_t mapping_size;
    uintptr_t thread_pointer;
    uintptr_t dtv;
    size_t dtv_offset;
    size_t dtv_count;
    size_t payload_size;
    size_t object_count;
} StaticTlsLayout;

typedef struct {
    uintptr_t mapping;
    size_t mapping_size;
    uintptr_t dtv;
    size_t dtv_count;
    size_t calls;
    int armed;
} DynamicTlsState;

typedef struct {
    size_t calls;
} InitializerEvidence;

typedef struct {
    const char *name;
    size_t name_length;
    ObjectName provider;
    int explicit_version;
    int has_provider;
} SymbolVersionRequirement;

typedef struct {
    uintptr_t fini_function;
    uintptr_t fini_array[MAXIMUM_INITIALIZERS];
    size_t fini_array_count;
} FinalizerObject;

typedef struct {
    FinalizerObject objects[MAXIMUM_LOADED_OBJECTS];
    size_t object_count;
    size_t expected_calls;
    uintptr_t tls_instance;
    int armed;
} FinalizationPlan;

typedef struct {
    size_t calls;
} FinalizerEvidence;

_Static_assert(sizeof(Elf64Header) == 64, "ELF64 header layout");
_Static_assert(sizeof(Elf64ProgramHeader) == 56, "ELF64 program header layout");
_Static_assert(sizeof(Elf64Dynamic) == 16, "ELF64 dynamic entry layout");
_Static_assert(sizeof(Elf64Symbol) == 24, "ELF64 symbol layout");
_Static_assert(sizeof(Elf64Rela) == 24, "ELF64 relocation layout");
_Static_assert(sizeof(Elf64VersionDefinition) == 20,
               "ELF64 version definition layout");
_Static_assert(sizeof(Elf64VersionDefinitionAuxiliary) == 8,
               "ELF64 version definition auxiliary layout");
_Static_assert(sizeof(Elf64VersionRequirement) == 16,
               "ELF64 version requirement layout");
_Static_assert(sizeof(Elf64VersionRequirementAuxiliary) == 16,
               "ELF64 version requirement auxiliary layout");

static FinalizationPlan finalization_plan;
static DynamicTlsState dynamic_tls_state;

extern void _start(void);
uintptr_t arach_runtime_linker_start(const uintptr_t *stack);
void arach_runtime_linker_finalize(void);
static void *arach_tls_get_addr(const DynamicTlsIndex *index);

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

static int valid_object_name_byte(char value) {
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '.' || value == '-' ||
           value == '_' || value == '+';
}

static int copy_object_name(const char *value, size_t capacity,
                            ObjectName *result) {
    if (capacity == 0) {
        return 0;
    }
    size_t length = 0;
    while (length < capacity && length <= MAXIMUM_OBJECT_NAME_BYTES &&
           value[length] != '\0') {
        if (!valid_object_name_byte(value[length])) {
            return 0;
        }
        ++length;
    }
    if (length == 0 || length > MAXIMUM_OBJECT_NAME_BYTES ||
        length == capacity || value[length] != '\0' || value[0] == '.' ||
        value[length - 1] == '.') {
        return 0;
    }
    for (size_t index = 0; index < length; ++index) {
        result->bytes[index] = value[index];
    }
    result->bytes[length] = '\0';
    result->length = length;
    return 1;
}

static int object_names_equal(const ObjectName *left,
                              const ObjectName *right) {
    return left->length == right->length &&
           bytes_equal(left->bytes, right->bytes, left->length);
}

static int object_name_equals_literal(const ObjectName *name,
                                      const char *literal,
                                      size_t literal_length) {
    return name->length == literal_length &&
           bytes_equal(name->bytes, literal, literal_length);
}

static int search_directories_equal(const SearchDirectory *left,
                                    const SearchDirectory *right) {
    return left->length == right->length &&
           bytes_equal(left->bytes, right->bytes, left->length);
}

static int search_directory_equals_literal(const SearchDirectory *directory,
                                           const char *literal,
                                           size_t literal_length) {
    return directory->length == literal_length &&
           bytes_equal(directory->bytes, literal, literal_length);
}

static int copy_search_directory(const char *value, size_t length,
                                 SearchDirectory *result) {
    if (length < 2 || length > MAXIMUM_RUNPATH_DIRECTORY_BYTES ||
        value[0] != '/' || value[length - 1] == '/') {
        return 0;
    }
    size_t component_start = 1;
    for (size_t index = 1; index <= length; ++index) {
        if (index == length || value[index] == '/') {
            size_t component_length = index - component_start;
            if (component_length == 0 ||
                (component_length == 1 && value[component_start] == '.') ||
                (component_length == 2 && value[component_start] == '.' &&
                 value[component_start + 1] == '.')) {
                return 0;
            }
            component_start = index + 1;
        } else if (!valid_object_name_byte(value[index])) {
            return 0;
        }
    }
    for (size_t index = 0; index < length; ++index) {
        result->bytes[index] = value[index];
    }
    result->bytes[length] = '\0';
    result->length = length;
    return 1;
}

static int parse_search_path(const char *value, size_t capacity,
                             SearchPath *result) {
    result->count = 0;
    size_t component_start = 0;
    for (size_t cursor = 0;
         cursor < capacity && cursor <= MAXIMUM_RUNPATH_STRING_BYTES;
         ++cursor) {
        char byte = value[cursor];
        if (byte != ':' && byte != '\0') {
            if (cursor == MAXIMUM_RUNPATH_STRING_BYTES) {
                return 0;
            }
            continue;
        }
        size_t length = cursor - component_start;
        if (length == 0 || result->count == MAXIMUM_RUNPATH_DIRECTORIES ||
            !copy_search_directory(&value[component_start], length,
                                   &result->directories[result->count])) {
            return 0;
        }
        for (size_t prior = 0; prior < result->count; ++prior) {
            if (search_directories_equal(
                    &result->directories[prior],
                    &result->directories[result->count])) {
                return 0;
            }
        }
        ++result->count;
        if (byte == '\0') {
            return 1;
        }
        component_start = cursor + 1;
    }
    return 0;
}

static int build_object_path_in_directory(
    const SearchDirectory *directory, const ObjectName *name, char *path,
    size_t capacity, size_t *path_length) {
    size_t directory_length = directory == NULL ? 0 : directory->length;
    size_t length = 0;
    if (directory_length > MAXIMUM_OBJECT_PATH_BYTES ||
        name->length > MAXIMUM_OBJECT_PATH_BYTES - directory_length ||
        name->length + directory_length > MAXIMUM_OBJECT_PATH_BYTES - 1) {
        return 0;
    }
    length = directory_length + 1 + name->length;
    if (length >= capacity || length > MAXIMUM_OBJECT_PATH_BYTES) {
        return 0;
    }
    for (size_t index = 0; index < directory_length; ++index) {
        path[index] = directory->bytes[index];
    }
    path[directory_length] = '/';
    for (size_t index = 0; index < name->length; ++index) {
        path[directory_length + 1 + index] = name->bytes[index];
    }
    path[length] = '\0';
    *path_length = length;
    return 1;
}

static int checked_add(uintptr_t base, uint64_t offset, uintptr_t *result) {
    if (offset > UINTPTR_MAX - base) {
        return 0;
    }
    *result = base + (uintptr_t)offset;
    return 1;
}

static int checked_addend(uintptr_t base, int64_t addend,
                          uintptr_t *result) {
    if (addend >= 0) {
        return checked_add(base, (uint64_t)addend, result);
    }
    uint64_t magnitude = (uint64_t)(-(addend + 1)) + 1;
    if (magnitude > base) {
        return 0;
    }
    *result = base - (uintptr_t)magnitude;
    return 1;
}

static int checked_range(uintptr_t start, size_t length, uintptr_t *end) {
    if (length > UINTPTR_MAX - start) {
        return 0;
    }
    *end = start + length;
    return 1;
}

static int checked_size_add(size_t left, size_t right, size_t *result) {
    if (right > SIZE_MAX - left) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static int resolve_dynamic_tls_index(const DynamicTlsEntry *dtv,
                                     size_t dtv_count,
                                     const DynamicTlsIndex *index,
                                     uintptr_t *address) {
    if (dtv == NULL || index == NULL || address == NULL || dtv_count < 2 ||
        dtv_count > MAXIMUM_LOADED_OBJECTS + 1 ||
        dtv[0].address != dtv_count - 1 || dtv[0].size != 1 ||
        index->module == 0 || index->module >= dtv_count) {
        return 0;
    }
    const DynamicTlsEntry *entry = &dtv[index->module];
    if (entry->address == 0 || entry->size == 0 ||
        index->offset >= entry->size ||
        !checked_add(entry->address, index->offset, address)) {
        return 0;
    }
    return 1;
}

static void *arach_tls_get_addr(const DynamicTlsIndex *index) {
    uintptr_t dtv_address = 0;
    uintptr_t address = 0;
    uintptr_t mapping_end = 0;
    uintptr_t dtv_end = 0;
    size_t dtv_bytes = 0;
    __asm__ volatile("movq %%fs:8, %0" : "=r"(dtv_address));
    if (!dynamic_tls_state.armed ||
        dtv_address != dynamic_tls_state.dtv ||
        dtv_address % _Alignof(DynamicTlsEntry) != 0 ||
        dynamic_tls_state.dtv_count < 2 ||
        dynamic_tls_state.dtv_count > MAXIMUM_LOADED_OBJECTS + 1 ||
        dynamic_tls_state.dtv_count >
            SIZE_MAX / sizeof(DynamicTlsEntry) ||
        !checked_range(dynamic_tls_state.mapping,
                       dynamic_tls_state.mapping_size, &mapping_end) ||
        (dtv_bytes = dynamic_tls_state.dtv_count *
                         sizeof(DynamicTlsEntry)) == 0 ||
        !checked_range(dtv_address, dtv_bytes, &dtv_end) ||
        dtv_address < dynamic_tls_state.mapping || dtv_end > mapping_end ||
        dynamic_tls_state.calls == MAXIMUM_RELOCATIONS ||
        !resolve_dynamic_tls_index((const DynamicTlsEntry *)dtv_address,
                                   dynamic_tls_state.dtv_count, index,
                                   &address) ||
        address < dynamic_tls_state.mapping || address >= mapping_end) {
        fail_with(shared_dynamic_tls_failure,
                  sizeof(shared_dynamic_tls_failure) - 1);
    }
    ++dynamic_tls_state.calls;
    return (void *)address;
}

static int round_to_pages(size_t length, size_t *rounded) {
    if (length == 0 || length > SIZE_MAX - (PAGE_SIZE - 1)) {
        return 0;
    }
    *rounded = (length + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);
    return 1;
}

static int is_power_of_two(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

static int align_size(size_t value, size_t alignment, size_t *aligned) {
    if (!is_power_of_two(alignment) || value > SIZE_MAX - (alignment - 1)) {
        return 0;
    }
    *aligned = (value + alignment - 1) & ~(alignment - 1);
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

static int discover_main_dependencies(const Elf64ProgramHeader *headers,
                                      size_t header_count,
                                      uintptr_t *main_base,
                                      DependencyNames *dependencies) {
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
        dynamic_program->memory_size % sizeof(Elf64Dynamic) != 0 ||
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
    size_t needed_offsets[MAXIMUM_NEEDED_ENTRIES];
    size_t needed_count = 0;
    size_t string_size = 0;
    uintptr_t string_table = 0;
    int has_terminator = 0;
    size_t entries = (size_t)dynamic_program->memory_size / sizeof(*dynamic);
    for (size_t index = 0; index < entries; ++index) {
        switch (dynamic[index].tag) {
        case DYNAMIC_NULL:
            has_terminator = 1;
            index = entries;
            break;
        case DYNAMIC_NEEDED:
            if (needed_count == MAXIMUM_NEEDED_ENTRIES ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            needed_offsets[needed_count] = (size_t)dynamic[index].value;
            ++needed_count;
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
    if (!has_terminator || needed_count == 0 || string_table == 0 ||
        string_size == 0 ||
        !main_range_contains(headers, header_count, *main_base, string_table,
                             string_size)) {
        return 0;
    }
    dependencies->count = 0;
    for (size_t index = 0; index < needed_count; ++index) {
        if (needed_offsets[index] >= string_size ||
            !copy_object_name(
                (const char *)(string_table + needed_offsets[index]),
                string_size - needed_offsets[index],
                &dependencies->names[dependencies->count])) {
            return 0;
        }
        for (size_t prior = 0; prior < dependencies->count; ++prior) {
            if (object_names_equal(&dependencies->names[prior],
                                   &dependencies->names[dependencies->count])) {
                return 0;
            }
        }
        ++dependencies->count;
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

static int tls_program_matches_load(const LoadedObject *object,
                                    const Elf64ProgramHeader *tls) {
    for (size_t index = 0; index < object->header->program_header_count;
         ++index) {
        const Elf64ProgramHeader *load = &object->headers[index];
        if (load->type != PROGRAM_LOAD ||
            tls->virtual_address < load->virtual_address) {
            continue;
        }
        uint64_t virtual_delta =
            tls->virtual_address - load->virtual_address;
        if (virtual_delta > load->memory_size ||
            tls->memory_size > load->memory_size - virtual_delta) {
            continue;
        }
        if (tls->offset < load->offset) {
            return 0;
        }
        uint64_t file_delta = tls->offset - load->offset;
        return file_delta == virtual_delta &&
               file_delta <= load->file_size &&
               tls->file_size <= load->file_size - file_delta;
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

static void copy_bytes(uint8_t *destination, const uint8_t *source,
                       size_t length) {
    for (size_t index = 0; index < length; ++index) {
        destination[index] = source[index];
    }
}

static int parse_shared_dynamic(LoadedObject *object) {
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
    result->init_function = 0;
    result->init_array = 0;
    result->fini_function = 0;
    result->fini_array = 0;
    result->version_symbols = 0;
    result->version_definitions = 0;
    result->version_requirements = 0;
    result->string_size = 0;
    result->relocation_size = 0;
    result->jump_relocation_size = 0;
    result->relocation_entry_size = 0;
    result->symbol_entry_size = 0;
    result->init_array_size = 0;
    result->fini_array_size = 0;
    result->version_definition_count = 0;
    result->version_requirement_count = 0;
    result->soname_offset = 0;
    result->runpath_offset = 0;
    for (size_t index = 0; index < MAXIMUM_NEEDED_ENTRIES; ++index) {
        result->needed_offsets[index] = 0;
    }
    result->needed_count = 0;
    result->relative_count = 0;
    result->plt_relocation_type = 0;
    result->flags = 0;
    result->flags_1 = 0;
    result->has_soname = 0;
    result->has_runpath = 0;
    result->has_relative_count = 0;
    result->has_plt_relocation_type = 0;
    result->has_flags = 0;
    result->has_flags_1 = 0;
    result->has_symbolic = 0;
    result->has_bind_now = 0;
    result->has_init_function = 0;
    result->has_init_array = 0;
    result->has_init_array_size = 0;
    result->has_fini_function = 0;
    result->has_fini_array = 0;
    result->has_fini_array_size = 0;
    result->has_version_symbols = 0;
    result->has_version_definitions = 0;
    result->has_version_definition_count = 0;
    result->has_version_requirements = 0;
    result->has_version_requirement_count = 0;
    result->runpath.count = 0;
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
            if (result->needed_count == MAXIMUM_NEEDED_ENTRIES ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->needed_offsets[result->needed_count] =
                (size_t)dynamic[index].value;
            ++result->needed_count;
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
        case DYNAMIC_RUNPATH:
            if (result->has_runpath || dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->runpath_offset = (size_t)dynamic[index].value;
            result->has_runpath = 1;
            break;
        case DYNAMIC_INIT:
            if (result->has_init_function ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->init_function = pointer;
            result->has_init_function = 1;
            break;
        case DYNAMIC_INIT_ARRAY:
            if (result->has_init_array ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->init_array = pointer;
            result->has_init_array = 1;
            break;
        case DYNAMIC_INIT_ARRAY_SIZE:
            if (result->has_init_array_size || dynamic[index].value == 0 ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->init_array_size = (size_t)dynamic[index].value;
            result->has_init_array_size = 1;
            break;
        case DYNAMIC_FINI:
            if (result->has_fini_function ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->fini_function = pointer;
            result->has_fini_function = 1;
            break;
        case DYNAMIC_FINI_ARRAY:
            if (result->has_fini_array ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->fini_array = pointer;
            result->has_fini_array = 1;
            break;
        case DYNAMIC_FINI_ARRAY_SIZE:
            if (result->has_fini_array_size || dynamic[index].value == 0 ||
                dynamic[index].value > SIZE_MAX) {
                return 0;
            }
            result->fini_array_size = (size_t)dynamic[index].value;
            result->has_fini_array_size = 1;
            break;
        case DYNAMIC_SYMBOLIC:
            if (result->has_symbolic || dynamic[index].value != 0) {
                return 0;
            }
            result->has_symbolic = 1;
            break;
        case DYNAMIC_BIND_NOW:
            if (result->has_bind_now || dynamic[index].value != 0) {
                return 0;
            }
            result->has_bind_now = 1;
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
        case DYNAMIC_VERSION_SYMBOL:
            if (result->has_version_symbols ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->version_symbols = pointer;
            result->has_version_symbols = 1;
            break;
        case DYNAMIC_VERSION_DEFINITION:
            if (result->has_version_definitions ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->version_definitions = pointer;
            result->has_version_definitions = 1;
            break;
        case DYNAMIC_VERSION_DEFINITION_COUNT:
            if (result->has_version_definition_count ||
                dynamic[index].value == 0 ||
                dynamic[index].value > MAXIMUM_VERSION_DEFINITIONS) {
                return 0;
            }
            result->version_definition_count =
                (size_t)dynamic[index].value;
            result->has_version_definition_count = 1;
            break;
        case DYNAMIC_VERSION_REQUIREMENT:
            if (result->has_version_requirements ||
                !checked_add(object->base, dynamic[index].value, &pointer)) {
                return 0;
            }
            result->version_requirements = pointer;
            result->has_version_requirements = 1;
            break;
        case DYNAMIC_VERSION_REQUIREMENT_COUNT:
            if (result->has_version_requirement_count ||
                dynamic[index].value == 0 ||
                dynamic[index].value > MAXIMUM_VERSION_REQUIREMENTS) {
                return 0;
            }
            result->version_requirement_count =
                (size_t)dynamic[index].value;
            result->has_version_requirement_count = 1;
            break;
        case DYNAMIC_REL:
        case DYNAMIC_REL_SIZE:
        case DYNAMIC_REL_ENTRY:
        case DYNAMIC_DEBUG:
        case DYNAMIC_TEXT_RELOCATION:
        case DYNAMIC_RPATH:
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
        !result->has_soname ||
        result->soname_offset >= result->string_size ||
        !mapped_range_contains(object->loads, object->load_count, result->hash,
                               2 * sizeof(uint32_t), 0) ||
        !mapped_range_contains(object->loads, object->load_count,
                               result->string_table, result->string_size, 0) ||
        result->flags &
                ~(uint64_t)(DYNAMIC_FLAG_SYMBOLIC | DYNAMIC_FLAG_BIND_NOW |
                            DYNAMIC_FLAG_STATIC_TLS) ||
        result->flags_1 & ~(uint64_t)DYNAMIC_FLAG_1_NOW ||
        (result->has_symbolic !=
         ((result->flags & DYNAMIC_FLAG_SYMBOLIC) != 0)) ||
        ((result->flags & DYNAMIC_FLAG_STATIC_TLS) != 0 &&
         object->tls_program == NULL) ||
        (result->has_init_function &&
         !mapped_range_contains(object->loads, object->load_count,
                                result->init_function, 1,
                                PROGRAM_EXECUTABLE)) ||
        (result->has_init_array != result->has_init_array_size) ||
        (result->has_init_array &&
         (result->init_array % _Alignof(uintptr_t) != 0 ||
          result->init_array_size % sizeof(uintptr_t) != 0 ||
          result->init_array_size / sizeof(uintptr_t) >
              MAXIMUM_INITIALIZERS ||
          !mapped_range_contains(object->loads, object->load_count,
                                 result->init_array,
                                 result->init_array_size,
                                 PROGRAM_WRITABLE))) ||
        (result->has_fini_function &&
         !mapped_range_contains(object->loads, object->load_count,
                                result->fini_function, 1,
                                PROGRAM_EXECUTABLE)) ||
        (result->has_fini_array != result->has_fini_array_size) ||
        (result->has_fini_array &&
         (result->fini_array % _Alignof(uintptr_t) != 0 ||
          result->fini_array_size % sizeof(uintptr_t) != 0 ||
          result->fini_array_size / sizeof(uintptr_t) >
              MAXIMUM_INITIALIZERS ||
          !mapped_range_contains(object->loads, object->load_count,
                                 result->fini_array,
                                 result->fini_array_size,
                                 PROGRAM_WRITABLE))) ||
        (result->has_version_definitions !=
         result->has_version_definition_count) ||
        (result->has_version_requirements !=
         result->has_version_requirement_count) ||
        (result->has_version_symbols !=
         (result->has_version_definitions ||
          result->has_version_requirements))) {
        return 0;
    }
    if (result->has_runpath &&
        (result->runpath_offset >= result->string_size ||
         !parse_search_path(
             (const char *)(result->string_table + result->runpath_offset),
             result->string_size - result->runpath_offset,
             &result->runpath))) {
        return 0;
    }
    ObjectName soname;
    if (!copy_object_name(
            (const char *)(result->string_table + result->soname_offset),
            result->string_size - result->soname_offset, &soname) ||
        !object_names_equal(&soname, &object->name)) {
        return 0;
    }
    for (size_t index = 0; index < result->needed_count; ++index) {
        ObjectName dependency;
        if (result->needed_offsets[index] >= result->string_size ||
            !copy_object_name(
                (const char *)(result->string_table +
                               result->needed_offsets[index]),
                result->string_size - result->needed_offsets[index],
                &dependency)) {
            return 0;
        }
        for (size_t prior = 0; prior < index; ++prior) {
            ObjectName earlier;
            if (!copy_object_name(
                    (const char *)(result->string_table +
                                   result->needed_offsets[prior]),
                    result->string_size - result->needed_offsets[prior],
                    &earlier) ||
                object_names_equal(&dependency, &earlier)) {
                return 0;
            }
        }
    }
    int has_relocations = result->relocations != 0 ||
                          result->relocation_size != 0 ||
                          result->relocation_entry_size != 0;
    if (has_relocations) {
        if (result->relocations == 0 || result->relocation_size == 0 ||
            result->relocation_entry_size != sizeof(Elf64Rela) ||
            result->relocation_size % sizeof(Elf64Rela) != 0 ||
            result->relocation_size / sizeof(Elf64Rela) >
                MAXIMUM_RELOCATIONS ||
            !mapped_range_contains(object->loads, object->load_count,
                                   result->relocations,
                                   result->relocation_size, 0)) {
            return 0;
        }
    } else if (result->has_relative_count) {
        return 0;
    }
    if (result->has_relative_count &&
        result->relative_count > result->relocation_size / sizeof(Elf64Rela)) {
        return 0;
    }
    int has_jump_relocations = result->jump_relocations != 0 ||
                               result->jump_relocation_size != 0 ||
                               result->plt_got != 0 ||
                               result->has_plt_relocation_type;
    if (has_jump_relocations) {
        if (result->jump_relocations == 0 ||
            result->jump_relocation_size == 0 || result->plt_got == 0 ||
            !result->has_plt_relocation_type ||
            result->plt_relocation_type != DYNAMIC_RELA ||
            result->jump_relocation_size % sizeof(Elf64Rela) != 0 ||
            result->jump_relocation_size / sizeof(Elf64Rela) >
                MAXIMUM_RELOCATIONS ||
            (result->flags & DYNAMIC_FLAG_BIND_NOW) == 0 ||
            !result->has_flags_1 ||
            result->flags_1 != DYNAMIC_FLAG_1_NOW ||
            !mapped_range_contains(object->loads, object->load_count,
                                   result->jump_relocations,
                                   result->jump_relocation_size, 0) ||
            !mapped_range_contains(object->loads, object->load_count,
                                   result->plt_got, sizeof(uintptr_t),
                                   PROGRAM_WRITABLE)) {
            return 0;
        }
    } else if (result->has_flags_1 ||
               (result->flags & DYNAMIC_FLAG_BIND_NOW) != 0 ||
               result->has_bind_now) {
        return 0;
    }
    return 1;
}

static int object_dependency_name(const LoadedObject *object, size_t index,
                                  ObjectName *name) {
    const SharedDynamic *dynamic = &object->dynamic;
    if (index >= dynamic->needed_count ||
        dynamic->needed_offsets[index] >= dynamic->string_size) {
        return 0;
    }
    return copy_object_name(
        (const char *)(dynamic->string_table + dynamic->needed_offsets[index]),
        dynamic->string_size - dynamic->needed_offsets[index], name);
}

static int graph_find_object(const ObjectGraph *graph, const ObjectName *name,
                             size_t *object_index) {
    for (size_t index = 0; index < graph->object_count; ++index) {
        if (object_names_equal(&graph->objects[index].name, name)) {
            *object_index = index;
            return 1;
        }
    }
    return 0;
}

static int compute_relocation_order(ObjectGraph *graph) {
    int placed[MAXIMUM_LOADED_OBJECTS] = {0};
    graph->relocation_count = 0;
    while (graph->relocation_count < graph->object_count) {
        size_t before = graph->relocation_count;
        for (size_t index = 0; index < graph->object_count; ++index) {
            if (placed[index]) {
                continue;
            }
            int dependencies_ready = 1;
            for (size_t dependency = 0;
                 dependency < graph->objects[index].dependency_count;
                 ++dependency) {
                size_t provider =
                    graph->objects[index].dependencies[dependency];
                if (provider >= graph->object_count || !placed[provider]) {
                    dependencies_ready = 0;
                    break;
                }
            }
            if (dependencies_ready) {
                graph->relocation_order[graph->relocation_count] = index;
                ++graph->relocation_count;
                placed[index] = 1;
            }
        }
        if (graph->relocation_count == before) {
            return 0;
        }
    }
    return 1;
}

static int graph_has_edge(const ObjectGraph *graph, size_t consumer,
                          size_t provider) {
    if (consumer >= graph->object_count || provider >= graph->object_count) {
        return 0;
    }
    for (size_t index = 0;
         index < graph->objects[consumer].dependency_count; ++index) {
        if (graph->objects[consumer].dependencies[index] == provider) {
            return 1;
        }
    }
    return 0;
}

static int verify_probe_graph(const ObjectGraph *graph) {
    return graph->object_count == 4 && graph->relocation_count == 4 &&
           object_name_equals_literal(&graph->objects[0].name,
                                      expected_needed,
                                      sizeof(expected_needed) - 1) &&
           object_name_equals_literal(&graph->objects[1].name,
                                      expected_provider,
                                      sizeof(expected_provider) - 1) &&
           object_name_equals_literal(&graph->objects[2].name,
                                      expected_observer,
                                      sizeof(expected_observer) - 1) &&
           object_name_equals_literal(&graph->objects[3].name, expected_core,
                                      sizeof(expected_core) - 1) &&
           graph_has_edge(graph, 0, 1) && graph_has_edge(graph, 0, 2) &&
           graph_has_edge(graph, 1, 3) && graph_has_edge(graph, 2, 3) &&
           graph->objects[0].dependency_count == 2 &&
           graph->objects[1].dependency_count == 1 &&
           graph->objects[2].dependency_count == 1 &&
           graph->objects[3].dependency_count == 0 &&
           graph->relocation_order[0] == 3 &&
           graph->relocation_order[1] == 1 &&
           graph->relocation_order[2] == 2 &&
           graph->relocation_order[3] == 0;
}

static int object_path_equals_literal(const LoadedObject *object,
                                      const char *literal,
                                      size_t literal_length) {
    return object->path_length == literal_length &&
           bytes_equal(object->path, literal, literal_length) &&
           object->path[literal_length] == '\0';
}

static int has_expected_runpath(const LoadedObject *object) {
    return object->dynamic.has_runpath &&
           object->dynamic.runpath.count == 1 &&
           search_directory_equals_literal(
               &object->dynamic.runpath.directories[0], expected_runpath,
               sizeof(expected_runpath) - 1);
}

static int verify_probe_runpaths(const ObjectGraph *graph) {
    return graph->object_count == 4 &&
           !graph->objects[0].loaded_from_runpath &&
           graph->objects[1].loaded_from_runpath &&
           graph->objects[2].loaded_from_runpath &&
           graph->objects[3].loaded_from_runpath &&
           object_path_equals_literal(
               &graph->objects[0], expected_root_object_path,
               sizeof(expected_root_object_path) - 1) &&
           object_path_equals_literal(
               &graph->objects[1], expected_provider_path,
               sizeof(expected_provider_path) - 1) &&
           object_path_equals_literal(
               &graph->objects[2], expected_observer_path,
               sizeof(expected_observer_path) - 1) &&
           object_path_equals_literal(&graph->objects[3], expected_core_path,
                                      sizeof(expected_core_path) - 1) &&
           has_expected_runpath(&graph->objects[0]) &&
           has_expected_runpath(&graph->objects[1]) &&
           has_expected_runpath(&graph->objects[2]) &&
           !graph->objects[3].dynamic.has_runpath &&
           graph->objects[3].dynamic.runpath.count == 0;
}

static int dynamic_symbol_name(const LoadedObject *object,
                               const Elf64Symbol *symbol, const char **name,
                               size_t *name_length);
static int resolve_global_tls_symbol(const ObjectGraph *graph,
                                     size_t requester_index,
                                     const char *name, size_t name_length,
                                     const SymbolVersionRequirement *version,
                                     size_t *provider_index,
                                     const Elf64Symbol **provider_symbol);

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
    const uint32_t *buckets = &hash[2];
    const uint32_t *chains = &buckets[bucket_count];
    if (chains[0] != 0) {
        return 0;
    }
    for (uint32_t index = 0; index < bucket_count; ++index) {
        if (buckets[index] >= chain_count) {
            return 0;
        }
    }
    for (uint32_t index = 1; index < chain_count; ++index) {
        if (chains[index] >= chain_count) {
            return 0;
        }
        uint32_t symbol = index;
        uint32_t steps = 0;
        while (symbol != 0) {
            if (symbol >= chain_count || steps == chain_count) {
                return 0;
            }
            symbol = chains[symbol];
            ++steps;
        }
    }
    *symbol_count = chain_count;
    return 1;
}

static int dynamic_string_name(const LoadedObject *object, uint32_t offset,
                               const char **name, size_t *name_length) {
    if ((size_t)offset >= object->dynamic.string_size) {
        return 0;
    }
    const char *candidate =
        (const char *)(object->dynamic.string_table + (size_t)offset);
    size_t available = object->dynamic.string_size - (size_t)offset;
    size_t length = 0;
    while (length < available && length <= MAXIMUM_SYMBOL_NAME_BYTES &&
           candidate[length] != '\0') {
        ++length;
    }
    if (length == 0 || length > MAXIMUM_SYMBOL_NAME_BYTES ||
        length == available || candidate[length] != '\0') {
        return 0;
    }
    *name = candidate;
    *name_length = length;
    return 1;
}

static int is_tls_resolver_name(const char *name, size_t name_length) {
    return name_length == sizeof(tls_resolver_symbol) - 1 &&
           bytes_equal(name, tls_resolver_symbol, name_length);
}

static int is_tls_resolver_reference(const LoadedObject *object,
                                     const Elf64Symbol *symbol) {
    const char *name = NULL;
    size_t name_length = 0;
    return symbol->section_index == SYMBOL_UNDEFINED &&
           (symbol->information & 0x0f) == SYMBOL_NO_TYPE &&
           (symbol->information >> 4) == SYMBOL_BIND_GLOBAL &&
           symbol->other == SYMBOL_VISIBILITY_DEFAULT && symbol->value == 0 &&
           symbol->size == 0 &&
           dynamic_symbol_name(object, symbol, &name, &name_length) &&
           is_tls_resolver_name(name, name_length);
}

static uint32_t version_name_hash(const char *name, size_t length) {
    uint32_t hash = 0;
    for (size_t index = 0; index < length; ++index) {
        hash = (hash << 4) + (uint8_t)name[index];
        uint32_t high = hash & UINT32_C(0xf0000000);
        if (high != 0) {
            hash ^= high >> 24;
            hash &= ~high;
        }
    }
    return hash;
}

static int needed_object_index(const LoadedObject *object,
                               const ObjectName *name, size_t *index) {
    for (size_t candidate = 0;
         candidate < object->dynamic.needed_count; ++candidate) {
        size_t offset = object->dynamic.needed_offsets[candidate];
        ObjectName dependency;
        if (offset >= object->dynamic.string_size ||
            !copy_object_name(
                (const char *)(object->dynamic.string_table + offset),
                object->dynamic.string_size - offset, &dependency)) {
            return 0;
        }
        if (object_names_equal(&dependency, name)) {
            *index = candidate;
            return 1;
        }
    }
    return 0;
}

static int find_version_definition(const LoadedObject *object,
                                   uint16_t expected_index,
                                   const char **name,
                                   size_t *name_length) {
    if (!object->dynamic.has_version_definitions) {
        return expected_index == 0;
    }
    uintptr_t cursor = object->dynamic.version_definitions;
    int found = expected_index == 0;
    for (size_t entry = 0;
         entry < object->dynamic.version_definition_count; ++entry) {
        if (cursor % _Alignof(Elf64VersionDefinition) != 0 ||
            !mapped_range_contains(object->loads, object->load_count, cursor,
                                   sizeof(Elf64VersionDefinition), 0)) {
            return 0;
        }
        const Elf64VersionDefinition *definition =
            (const Elf64VersionDefinition *)cursor;
        uint16_t required_index = (uint16_t)(entry + 1);
        uint16_t required_flags =
            entry == 0 ? VERSION_FLAG_BASE : 0;
        if (definition->version != VERSION_CURRENT ||
            definition->flags != required_flags ||
            definition->index != required_index ||
            definition->auxiliary_count != 1 ||
            definition->auxiliary != sizeof(*definition)) {
            return 0;
        }
        uintptr_t auxiliary_address = 0;
        if (!checked_add(cursor, definition->auxiliary,
                         &auxiliary_address) ||
            auxiliary_address %
                    _Alignof(Elf64VersionDefinitionAuxiliary) !=
                0 ||
            !mapped_range_contains(
                object->loads, object->load_count, auxiliary_address,
                sizeof(Elf64VersionDefinitionAuxiliary), 0)) {
            return 0;
        }
        const Elf64VersionDefinitionAuxiliary *auxiliary =
            (const Elf64VersionDefinitionAuxiliary *)auxiliary_address;
        const char *definition_name = NULL;
        size_t definition_name_length = 0;
        if (auxiliary->next != 0 ||
            !dynamic_string_name(object, auxiliary->name,
                                 &definition_name,
                                 &definition_name_length) ||
            definition->hash != version_name_hash(
                                    definition_name,
                                    definition_name_length)) {
            return 0;
        }
        if (entry == 0) {
            if (!bounded_string_equals(
                    definition_name, definition_name_length + 1,
                    object->name.bytes, object->name.length)) {
                return 0;
            }
        } else if (bounded_string_equals(
                       definition_name, definition_name_length + 1,
                       object->name.bytes, object->name.length)) {
            return 0;
        }
        if (definition->index == expected_index) {
            if (name != NULL) {
                *name = definition_name;
            }
            if (name_length != NULL) {
                *name_length = definition_name_length;
            }
            found = 1;
        }
        if (entry + 1 == object->dynamic.version_definition_count) {
            if (definition->next != 0) {
                return 0;
            }
        } else {
            uintptr_t next = 0;
            if (definition->next !=
                    sizeof(*definition) +
                        sizeof(Elf64VersionDefinitionAuxiliary) ||
                !checked_add(cursor, definition->next, &next) ||
                next <= cursor) {
                return 0;
            }
            cursor = next;
        }
    }
    return found;
}

static int validate_version_requirements(const LoadedObject *object,
                                         uint64_t *index_mask) {
    *index_mask = 0;
    if (!object->dynamic.has_version_requirements) {
        return 1;
    }
    uintptr_t cursor = object->dynamic.version_requirements;
    uint64_t needed_mask = 0;
    size_t auxiliary_total = 0;
    size_t definition_count =
        object->dynamic.has_version_definitions
            ? object->dynamic.version_definition_count
            : 1;
    for (size_t entry = 0;
         entry < object->dynamic.version_requirement_count; ++entry) {
        if (cursor % _Alignof(Elf64VersionRequirement) != 0 ||
            !mapped_range_contains(object->loads, object->load_count, cursor,
                                   sizeof(Elf64VersionRequirement), 0)) {
            return 0;
        }
        const Elf64VersionRequirement *requirement =
            (const Elf64VersionRequirement *)cursor;
        const char *file_name = NULL;
        size_t file_name_length = 0;
        ObjectName provider;
        size_t needed_index = 0;
        if (requirement->version != VERSION_CURRENT ||
            requirement->auxiliary_count == 0 ||
            requirement->auxiliary_count >
                MAXIMUM_VERSION_AUXILIARIES ||
            auxiliary_total > (size_t)MAXIMUM_VERSION_AUXILIARIES -
                                  (size_t)requirement->auxiliary_count ||
            requirement->auxiliary != sizeof(*requirement) ||
            !dynamic_string_name(object, requirement->file, &file_name,
                                 &file_name_length) ||
            !copy_object_name(file_name, file_name_length + 1, &provider) ||
            !needed_object_index(object, &provider, &needed_index) ||
            needed_index >= 64 ||
            (needed_mask & (UINT64_C(1) << needed_index)) != 0) {
            return 0;
        }
        needed_mask |= UINT64_C(1) << needed_index;
        uintptr_t auxiliary_cursor = 0;
        if (!checked_add(cursor, requirement->auxiliary,
                         &auxiliary_cursor) ||
            auxiliary_cursor %
                    _Alignof(Elf64VersionRequirementAuxiliary) !=
                0) {
            return 0;
        }
        for (size_t auxiliary_index = 0;
             auxiliary_index < requirement->auxiliary_count;
             ++auxiliary_index) {
            if (!mapped_range_contains(
                    object->loads, object->load_count, auxiliary_cursor,
                    sizeof(Elf64VersionRequirementAuxiliary), 0)) {
                return 0;
            }
            const Elf64VersionRequirementAuxiliary *auxiliary =
                (const Elf64VersionRequirementAuxiliary *)auxiliary_cursor;
            const char *version_name = NULL;
            size_t version_name_length = 0;
            uint16_t version_index = auxiliary->other;
            if (auxiliary->flags != 0 ||
                (version_index & VERSION_INDEX_HIDDEN) != 0 ||
                version_index <= definition_count || version_index >= 64 ||
                version_index >
                    definition_count + MAXIMUM_VERSION_AUXILIARIES ||
                (*index_mask & (UINT64_C(1) << version_index)) != 0 ||
                !dynamic_string_name(object, auxiliary->name,
                                     &version_name,
                                     &version_name_length) ||
                auxiliary->hash != version_name_hash(
                                       version_name,
                                       version_name_length)) {
                return 0;
            }
            *index_mask |= UINT64_C(1) << version_index;
            ++auxiliary_total;
            if (auxiliary_index + 1 == requirement->auxiliary_count) {
                if (auxiliary->next != 0) {
                    return 0;
                }
            } else {
                uintptr_t next = 0;
                if (auxiliary->next != sizeof(*auxiliary) ||
                    !checked_add(auxiliary_cursor, auxiliary->next, &next) ||
                    next <= auxiliary_cursor) {
                    return 0;
                }
                auxiliary_cursor = next;
            }
        }
        if (entry + 1 == object->dynamic.version_requirement_count) {
            if (requirement->next != 0) {
                return 0;
            }
        } else {
            uintptr_t next = 0;
            size_t required_next =
                sizeof(*requirement) +
                (size_t)requirement->auxiliary_count *
                    sizeof(Elf64VersionRequirementAuxiliary);
            if (requirement->next != required_next ||
                !checked_add(cursor, requirement->next, &next) ||
                next <= cursor) {
                return 0;
            }
            cursor = next;
        }
    }
    uint64_t expected_mask = 0;
    for (size_t index = definition_count + 1;
         index <= definition_count + auxiliary_total; ++index) {
        if (index >= 64) {
            return 0;
        }
        expected_mask |= UINT64_C(1) << index;
    }
    return auxiliary_total != 0 && *index_mask == expected_mask;
}

static int find_version_requirement(
    const LoadedObject *object, uint16_t expected_index, const char **name,
    size_t *name_length, ObjectName *provider) {
    if (!object->dynamic.has_version_requirements) {
        return 0;
    }
    uintptr_t cursor = object->dynamic.version_requirements;
    for (size_t entry = 0;
         entry < object->dynamic.version_requirement_count; ++entry) {
        const Elf64VersionRequirement *requirement =
            (const Elf64VersionRequirement *)cursor;
        const char *file_name = NULL;
        size_t file_name_length = 0;
        uintptr_t auxiliary_cursor = 0;
        if (!dynamic_string_name(object, requirement->file, &file_name,
                                 &file_name_length) ||
            !copy_object_name(file_name, file_name_length + 1, provider) ||
            !checked_add(cursor, requirement->auxiliary,
                         &auxiliary_cursor)) {
            return 0;
        }
        for (size_t auxiliary_index = 0;
             auxiliary_index < requirement->auxiliary_count;
             ++auxiliary_index) {
            const Elf64VersionRequirementAuxiliary *auxiliary =
                (const Elf64VersionRequirementAuxiliary *)auxiliary_cursor;
            if (auxiliary->other == expected_index) {
                return dynamic_string_name(object, auxiliary->name, name,
                                           name_length);
            }
            if (auxiliary_index + 1 < requirement->auxiliary_count &&
                !checked_add(auxiliary_cursor, auxiliary->next,
                             &auxiliary_cursor)) {
                return 0;
            }
        }
        if (entry + 1 < object->dynamic.version_requirement_count &&
            !checked_add(cursor, requirement->next, &cursor)) {
            return 0;
        }
    }
    return 0;
}

static int validate_symbol_versions(const LoadedObject *object,
                                    uint32_t symbol_count) {
    if (!object->dynamic.has_version_symbols) {
        return 1;
    }
    if (!mapped_range_contains(object->loads, object->load_count,
                               object->dynamic.version_symbols,
                               (size_t)symbol_count * sizeof(uint16_t), 0) ||
        object->dynamic.version_symbols % _Alignof(uint16_t) != 0 ||
        !find_version_definition(object, 0, NULL, NULL)) {
        return 0;
    }
    uint64_t requirement_mask = 0;
    if (!validate_version_requirements(object, &requirement_mask)) {
        return 0;
    }
    const uint16_t *versions =
        (const uint16_t *)object->dynamic.version_symbols;
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)object->dynamic.symbol_table;
    if (versions[0] != VERSION_INDEX_LOCAL) {
        return 0;
    }
    uint64_t referenced_definitions = 0;
    uint64_t referenced_requirements = 0;
    for (uint32_t index = 1; index < symbol_count; ++index) {
        uint16_t raw = versions[index];
        uint16_t version_index = raw & VERSION_INDEX_MASK;
        if (version_index == VERSION_INDEX_LOCAL) {
            if ((raw & VERSION_INDEX_HIDDEN) != 0 ||
                !is_tls_resolver_reference(object, &symbols[index])) {
                return 0;
            }
            continue;
        }
        if (version_index == VERSION_INDEX_GLOBAL &&
            (raw & VERSION_INDEX_HIDDEN) != 0) {
            return 0;
        }
        if (version_index == VERSION_INDEX_GLOBAL) {
            continue;
        }
        const char *version_name = NULL;
        size_t version_name_length = 0;
        if (symbols[index].section_index == SYMBOL_UNDEFINED) {
            ObjectName provider;
            if ((raw & VERSION_INDEX_HIDDEN) != 0 || version_index >= 64 ||
                !find_version_requirement(object, version_index,
                                          &version_name,
                                          &version_name_length, &provider)) {
                return 0;
            }
            referenced_requirements |= UINT64_C(1) << version_index;
        } else {
            if (version_index >= 64 ||
                !find_version_definition(object, version_index,
                                         &version_name,
                                         &version_name_length)) {
                return 0;
            }
            referenced_definitions |= UINT64_C(1) << version_index;
        }
    }
    uint64_t expected_definitions = 0;
    for (size_t index = 2;
         index <= object->dynamic.version_definition_count; ++index) {
        expected_definitions |= UINT64_C(1) << index;
    }
    return referenced_definitions == expected_definitions &&
           referenced_requirements == requirement_mask;
}

static int validate_dynamic_symbols(const LoadedObject *object) {
    uint32_t symbol_count = 0;
    if (!dynamic_symbol_count(object, &symbol_count) ||
        !validate_symbol_versions(object, symbol_count)) {
        return 0;
    }
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)object->dynamic.symbol_table;
    if (symbols[0].name != 0 || symbols[0].information != 0 ||
        symbols[0].other != 0 || symbols[0].section_index != SYMBOL_UNDEFINED ||
        symbols[0].value != 0 || symbols[0].size != 0) {
        return 0;
    }
    for (uint32_t index = 1; index < symbol_count; ++index) {
        const Elf64Symbol *symbol = &symbols[index];
        const char *name = NULL;
        size_t name_length = 0;
        uint8_t symbol_type = symbol->information & 0x0f;
        uint8_t symbol_binding = symbol->information >> 4;
        if (symbol_binding != SYMBOL_BIND_GLOBAL ||
            symbol->other != SYMBOL_VISIBILITY_DEFAULT ||
            !dynamic_symbol_name(object, symbol, &name, &name_length)) {
            return 0;
        }
        if (symbol_type != SYMBOL_NO_TYPE &&
            is_tls_resolver_name(name, name_length)) {
            return 0;
        }
        if (symbol_type == SYMBOL_OBJECT) {
            const char *version_name = NULL;
            size_t version_name_length = 0;
            if (symbol->section_index != SYMBOL_ABSOLUTE ||
                symbol->value != 0 || symbol->size != 0 ||
                !object->dynamic.has_version_symbols) {
                return 0;
            }
            const uint16_t *versions =
                (const uint16_t *)object->dynamic.version_symbols;
            uint16_t version_index =
                versions[index] & VERSION_INDEX_MASK;
            if (version_index <= VERSION_INDEX_GLOBAL ||
                !find_version_definition(object, version_index,
                                         &version_name,
                                         &version_name_length) ||
                name_length != version_name_length ||
                !bytes_equal(name, version_name, name_length)) {
                return 0;
            }
            continue;
        }
        if (symbol_type == SYMBOL_NO_TYPE) {
            if (!is_tls_resolver_reference(object, symbol)) {
                return 0;
            }
            continue;
        }
        if (symbol_type != SYMBOL_FUNCTION && symbol_type != SYMBOL_TLS) {
            return 0;
        }
        if (symbol->section_index == SYMBOL_UNDEFINED) {
            if (symbol->value != 0 || symbol->size != 0) {
                return 0;
            }
            continue;
        }
        if (symbol_type == SYMBOL_TLS) {
            if (object->tls_program == NULL || symbol->size == 0 ||
                symbol->value > object->tls_program->memory_size ||
                symbol->size >
                    object->tls_program->memory_size - symbol->value) {
                return 0;
            }
            continue;
        }
        uintptr_t address = 0;
        if (symbol->size == 0 || symbol->size > SIZE_MAX ||
            !checked_add(object->base, symbol->value, &address) ||
            !mapped_range_contains(object->loads, object->load_count, address,
                                   (size_t)symbol->size,
                                   PROGRAM_EXECUTABLE)) {
            return 0;
        }
    }
    return 1;
}

static int symbol_version_requirement(
    const LoadedObject *object, uint32_t symbol_index,
    SymbolVersionRequirement *requirement) {
    zero_bytes((uint8_t *)requirement, sizeof(*requirement));
    uint32_t symbol_count = 0;
    if (!dynamic_symbol_count(object, &symbol_count) ||
        symbol_index == 0 || symbol_index >= symbol_count) {
        return 0;
    }
    if (!object->dynamic.has_version_symbols) {
        return 1;
    }
    const uint16_t *versions =
        (const uint16_t *)object->dynamic.version_symbols;
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)object->dynamic.symbol_table;
    uint16_t raw = versions[symbol_index];
    uint16_t version_index = raw & VERSION_INDEX_MASK;
    if (version_index == VERSION_INDEX_GLOBAL) {
        return (raw & VERSION_INDEX_HIDDEN) == 0;
    }
    if (version_index == VERSION_INDEX_LOCAL) {
        return (raw & VERSION_INDEX_HIDDEN) == 0 &&
               is_tls_resolver_reference(object, &symbols[symbol_index]);
    }
    if (symbols[symbol_index].section_index == SYMBOL_UNDEFINED) {
        if (!find_version_requirement(
                object, version_index, &requirement->name,
                &requirement->name_length, &requirement->provider)) {
            return 0;
        }
        requirement->has_provider = 1;
    } else {
        if (!find_version_definition(object, version_index,
                                     &requirement->name,
                                     &requirement->name_length)) {
            return 0;
        }
        requirement->provider = object->name;
        requirement->has_provider = 1;
    }
    requirement->explicit_version = 1;
    return 1;
}

static int defined_symbol_matches_version(
    const LoadedObject *object, uint32_t symbol_index,
    const SymbolVersionRequirement *requirement) {
    if (requirement->has_provider &&
        !object_names_equal(&object->name, &requirement->provider)) {
        return 0;
    }
    if (!object->dynamic.has_version_symbols) {
        return !requirement->explicit_version;
    }
    const uint16_t *versions =
        (const uint16_t *)object->dynamic.version_symbols;
    uint16_t raw = versions[symbol_index];
    uint16_t version_index = raw & VERSION_INDEX_MASK;
    if (version_index == VERSION_INDEX_LOCAL) {
        return 0;
    }
    if (version_index == VERSION_INDEX_GLOBAL) {
        return !requirement->explicit_version;
    }
    const char *definition_name = NULL;
    size_t definition_name_length = 0;
    if (!find_version_definition(object, version_index, &definition_name,
                                 &definition_name_length)) {
        return 0;
    }
    if (!requirement->explicit_version) {
        return (raw & VERSION_INDEX_HIDDEN) == 0;
    }
    return definition_name_length == requirement->name_length &&
           bytes_equal(definition_name, requirement->name,
                       definition_name_length);
}

static int plan_static_tls(ObjectGraph *graph, StaticTlsLayout *layout) {
    zero_bytes((uint8_t *)layout, sizeof(*layout));
    size_t cursor = 0;
    size_t maximum_alignment = sizeof(uintptr_t);
    for (size_t index = 0; index < graph->object_count; ++index) {
        LoadedObject *object = &graph->objects[index];
        object->tls_instance = 0;
        object->tls_offset = 0;
        object->tls_module_id = 0;
        if (object->tls_program == NULL) {
            continue;
        }
        const Elf64ProgramHeader *tls = object->tls_program;
        size_t alignment = (size_t)tls->alignment;
        size_t offset = 0;
        if (alignment > maximum_alignment) {
            maximum_alignment = alignment;
        }
        if (!align_size(cursor, alignment, &offset) ||
            tls->memory_size > SIZE_MAX ||
            offset > MAXIMUM_STATIC_TLS_BYTES ||
            (size_t)tls->memory_size > MAXIMUM_STATIC_TLS_BYTES - offset) {
            return 0;
        }
        object->tls_offset = offset;
        object->tls_module_id = index + 1;
        cursor = offset + (size_t)tls->memory_size;
        ++layout->object_count;
    }
    if (layout->object_count == 0) {
        return 1;
    }
    size_t thread_control_end = 0;
    size_t dtv_bytes = 0;
    layout->dtv_count = graph->object_count + 1;
    if (layout->dtv_count > MAXIMUM_LOADED_OBJECTS + 1 ||
        layout->dtv_count > SIZE_MAX / sizeof(DynamicTlsEntry)) {
        return 0;
    }
    dtv_bytes = layout->dtv_count * sizeof(DynamicTlsEntry);
    if (!align_size(cursor, maximum_alignment, &layout->payload_size) ||
        layout->payload_size >
            MAXIMUM_STATIC_TLS_BYTES - (2 * sizeof(uintptr_t)) ||
        !checked_size_add(layout->payload_size, 2 * sizeof(uintptr_t),
                          &thread_control_end) ||
        !align_size(thread_control_end, _Alignof(DynamicTlsEntry),
                    &layout->dtv_offset) ||
        layout->dtv_offset > MAXIMUM_STATIC_TLS_BYTES ||
        dtv_bytes > MAXIMUM_STATIC_TLS_BYTES - layout->dtv_offset ||
        !round_to_pages(layout->dtv_offset + dtv_bytes,
                        &layout->mapping_size) ||
        layout->mapping_size > MAXIMUM_STATIC_TLS_BYTES) {
        return 0;
    }
    return 1;
}

static int install_static_tls(ObjectGraph *graph, StaticTlsLayout *layout) {
    zero_bytes((uint8_t *)&dynamic_tls_state, sizeof(dynamic_tls_state));
    if (!plan_static_tls(graph, layout)) {
        return 0;
    }
    if (layout->object_count == 0) {
        return 1;
    }
    long mapped = syscall6(SYS_MMAP, 0, layout->mapping_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, UINT64_MAX, 0);
    if (syscall_failed(mapped) || mapped == 0 ||
        (uintptr_t)mapped % PAGE_SIZE != 0) {
        return 0;
    }
    layout->mapping = (uintptr_t)mapped;
    zero_bytes((uint8_t *)layout->mapping, layout->mapping_size);
    for (size_t index = 0; index < graph->object_count; ++index) {
        LoadedObject *object = &graph->objects[index];
        if (object->tls_program == NULL) {
            continue;
        }
        uintptr_t source = 0;
        uintptr_t destination = 0;
        if (!checked_add(object->base,
                         object->tls_program->virtual_address, &source) ||
            !checked_add(layout->mapping, object->tls_offset, &destination)) {
            return 0;
        }
        object->tls_instance = destination;
        copy_bytes((uint8_t *)destination, (const uint8_t *)source,
                   (size_t)object->tls_program->file_size);
    }
    if (!checked_add(layout->mapping, layout->payload_size,
                     &layout->thread_pointer) ||
        !checked_add(layout->mapping, layout->dtv_offset, &layout->dtv)) {
        return 0;
    }
    DynamicTlsEntry *dtv = (DynamicTlsEntry *)layout->dtv;
    dtv[0].address = graph->object_count;
    dtv[0].size = 1;
    for (size_t index = 0; index < graph->object_count; ++index) {
        const LoadedObject *object = &graph->objects[index];
        if (object->tls_program == NULL || object->tls_module_id == 0 ||
            object->tls_module_id >= layout->dtv_count) {
            continue;
        }
        dtv[object->tls_module_id].address = object->tls_instance;
        dtv[object->tls_module_id].size =
            (size_t)object->tls_program->memory_size;
    }
    uintptr_t *thread_control = (uintptr_t *)layout->thread_pointer;
    thread_control[0] = layout->thread_pointer;
    thread_control[1] = layout->dtv;
    if (syscall3(SYS_ARCH_PRCTL, ARCH_SET_FS, layout->thread_pointer, 0) != 0) {
        return 0;
    }
    dynamic_tls_state.mapping = layout->mapping;
    dynamic_tls_state.mapping_size = layout->mapping_size;
    dynamic_tls_state.dtv = layout->dtv;
    dynamic_tls_state.dtv_count = layout->dtv_count;
    dynamic_tls_state.calls = 0;
    dynamic_tls_state.armed = 1;
    return 1;
}

static int apply_object_relocations(ObjectGraph *graph, size_t object_index,
                                    const StaticTlsLayout *tls_layout,
                                    RelocationEvidence *evidence) {
    if (object_index >= graph->object_count) {
        return 0;
    }
    const LoadedObject *object = &graph->objects[object_index];
    const Elf64Rela *relocations =
        (const Elf64Rela *)object->dynamic.relocations;
    size_t count = object->dynamic.relocation_size / sizeof(*relocations);
    uint32_t symbol_count = 0;
    if (count > MAXIMUM_RELOCATIONS ||
        !dynamic_symbol_count(object, &symbol_count)) {
        return 0;
    }
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)object->dynamic.symbol_table;
    for (size_t index = 0; index < count; ++index) {
        uint32_t relocation_type = (uint32_t)relocations[index].information;
        uint32_t symbol_index =
            (uint32_t)(relocations[index].information >> 32);
        uintptr_t target = 0;
        if (!checked_add(object->base, relocations[index].offset, &target) ||
            target % sizeof(uintptr_t) != 0 ||
            !mapped_range_contains(object->loads, object->load_count, target,
                                   sizeof(uintptr_t), PROGRAM_WRITABLE)) {
            return 0;
        }
        if (relocation_type == RELOCATION_X86_64_RELATIVE) {
            uintptr_t value = 0;
            if (symbol_index != 0 ||
                (object->dynamic.has_relative_count &&
                 index >= object->dynamic.relative_count) ||
                !checked_addend(object->base, relocations[index].addend,
                                &value) ||
                !mapped_range_contains(object->loads, object->load_count,
                                       value, 1, 0)) {
                return 0;
            }
            *(volatile uintptr_t *)target = value;
            if (*(volatile const uintptr_t *)target != value) {
                return 0;
            }
            ++evidence->relative;
            continue;
        }
        if (object->dynamic.has_relative_count &&
            index < object->dynamic.relative_count) {
            return 0;
        }
        if (relocation_type != RELOCATION_X86_64_DTPMOD64 &&
            relocation_type != RELOCATION_X86_64_DTPOFF64 &&
            relocation_type != RELOCATION_X86_64_TPOFF64) {
            return 0;
        }
        size_t provider_index = object_index;
        const Elf64Symbol *provider_symbol = NULL;
        SymbolVersionRequirement version_requirement;
        int versioned = 0;
        zero_bytes((uint8_t *)&version_requirement,
                   sizeof(version_requirement));
        if (symbol_index == 0) {
            if (relocation_type != RELOCATION_X86_64_DTPMOD64 ||
                relocations[index].addend != 0) {
                return 0;
            }
        } else {
            const Elf64Symbol *symbol = NULL;
            const char *name = NULL;
            size_t name_length = 0;
            if (symbol_index >= symbol_count) {
                return 0;
            }
            symbol = &symbols[symbol_index];
            if ((symbol->information & 0x0f) != SYMBOL_TLS ||
                (symbol->information >> 4) != SYMBOL_BIND_GLOBAL ||
                symbol->other != SYMBOL_VISIBILITY_DEFAULT ||
                !dynamic_symbol_name(object, symbol, &name, &name_length) ||
                !symbol_version_requirement(object, symbol_index,
                                            &version_requirement) ||
                !resolve_global_tls_symbol(
                    graph, object_index, name, name_length,
                    &version_requirement, &provider_index,
                    &provider_symbol)) {
                return 0;
            }
            versioned = version_requirement.explicit_version;
        }
        const LoadedObject *provider = &graph->objects[provider_index];
        uint64_t value = 0;
        if (provider->tls_program == NULL || provider->tls_instance == 0 ||
            provider->tls_module_id == 0) {
            return 0;
        }
        if (relocation_type == RELOCATION_X86_64_DTPMOD64) {
            if (relocations[index].addend != 0) {
                return 0;
            }
            value = (uint64_t)provider->tls_module_id;
        } else {
            if (provider_symbol == NULL) {
                return 0;
            }
            uintptr_t symbol_address = 0;
            if (!checked_add(provider->tls_instance, provider_symbol->value,
                             &symbol_address) ||
                !checked_addend(symbol_address, relocations[index].addend,
                                &symbol_address)) {
                return 0;
            }
            uintptr_t tls_end = 0;
            if (!checked_range(provider->tls_instance,
                               (size_t)provider->tls_program->memory_size,
                               &tls_end) ||
                symbol_address < provider->tls_instance ||
                symbol_address >= tls_end) {
                return 0;
            }
            if (relocation_type == RELOCATION_X86_64_DTPOFF64) {
                if (symbol_address < provider->tls_instance) {
                    return 0;
                }
                value = (uint64_t)(symbol_address - provider->tls_instance);
            } else {
                uint64_t magnitude = 0;
                if (tls_layout->thread_pointer == 0) {
                    return 0;
                }
                if (symbol_address >= tls_layout->thread_pointer) {
                    value = (uint64_t)(symbol_address -
                                       tls_layout->thread_pointer);
                    if (value > INT64_MAX) {
                        return 0;
                    }
                } else {
                    magnitude = (uint64_t)(tls_layout->thread_pointer -
                                           symbol_address);
                    if (magnitude > (uint64_t)INT64_MAX + 1) {
                        return 0;
                    }
                    value = UINT64_C(0) - magnitude;
                }
            }
        }
        *(volatile uint64_t *)target = value;
        if (*(volatile const uint64_t *)target != value) {
            return 0;
        }
        ++evidence->tls;
        if (versioned) {
            ++evidence->versioned;
        }
    }
    return 1;
}

static int find_exported_symbol_versioned(
    const LoadedObject *object, const char *expected_name,
    size_t expected_name_length,
    const SymbolVersionRequirement *version_requirement,
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
            defined_symbol_matches_version(object, index,
                                           version_requirement) &&
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

static int find_exported_symbol(const LoadedObject *object,
                                const char *expected_name,
                                size_t expected_name_length,
                                uintptr_t *symbol_address) {
    SymbolVersionRequirement version_requirement;
    zero_bytes((uint8_t *)&version_requirement,
               sizeof(version_requirement));
    return find_exported_symbol_versioned(
        object, expected_name, expected_name_length, &version_requirement,
        symbol_address);
}

static int dynamic_symbol_name(const LoadedObject *object,
                               const Elf64Symbol *symbol, const char **name,
                               size_t *name_length) {
    if (symbol->name >= object->dynamic.string_size) {
        return 0;
    }
    const char *candidate =
        (const char *)(object->dynamic.string_table + symbol->name);
    size_t available = object->dynamic.string_size - symbol->name;
    size_t length = 0;
    while (length < available && length <= MAXIMUM_SYMBOL_NAME_BYTES &&
           candidate[length] != '\0') {
        ++length;
    }
    if (length == 0 || length > MAXIMUM_SYMBOL_NAME_BYTES ||
        length == available || candidate[length] != '\0') {
        return 0;
    }
    *name = candidate;
    *name_length = length;
    return 1;
}

static int find_exported_tls_symbol(
    const LoadedObject *object, const char *expected_name,
    size_t expected_name_length,
    const SymbolVersionRequirement *version_requirement,
    const Elf64Symbol **symbol) {
    uint32_t symbol_count = 0;
    if (object->tls_program == NULL ||
        !dynamic_symbol_count(object, &symbol_count)) {
        return 0;
    }
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)object->dynamic.symbol_table;
    for (uint32_t index = 1; index < symbol_count; ++index) {
        if (symbols[index].section_index == SYMBOL_UNDEFINED ||
            (symbols[index].information & 0x0f) != SYMBOL_TLS ||
            (symbols[index].information >> 4) != SYMBOL_BIND_GLOBAL ||
            symbols[index].other != SYMBOL_VISIBILITY_DEFAULT ||
            symbols[index].size == 0 ||
            symbols[index].value > object->tls_program->memory_size ||
            symbols[index].size >
                object->tls_program->memory_size - symbols[index].value ||
            !defined_symbol_matches_version(object, index,
                                            version_requirement)) {
            continue;
        }
        const char *name = NULL;
        size_t name_length = 0;
        if (dynamic_symbol_name(object, &symbols[index], &name,
                                &name_length) &&
            name_length == expected_name_length &&
            bytes_equal(name, expected_name, name_length)) {
            *symbol = &symbols[index];
            return 1;
        }
    }
    return 0;
}

static int resolve_global_tls_symbol(const ObjectGraph *graph,
                                     size_t requester_index,
                                     const char *name, size_t name_length,
                                     const SymbolVersionRequirement *version,
                                     size_t *provider_index,
                                     const Elf64Symbol **provider_symbol) {
    if (requester_index >= graph->object_count || name_length == 0 ||
        name_length > MAXIMUM_SYMBOL_NAME_BYTES) {
        return 0;
    }
    const LoadedObject *requester = &graph->objects[requester_index];
    if (requester->dynamic.has_symbolic &&
        find_exported_tls_symbol(requester, name, name_length,
                                 version, provider_symbol)) {
        *provider_index = requester_index;
        return 1;
    }
    for (size_t index = 0; index < graph->object_count; ++index) {
        if (index != requester_index &&
            find_exported_tls_symbol(&graph->objects[index], name,
                                     name_length, version,
                                     provider_symbol)) {
            *provider_index = index;
            return 1;
        }
    }
    if (!requester->dynamic.has_symbolic &&
        find_exported_tls_symbol(requester, name, name_length,
                                 version, provider_symbol)) {
        *provider_index = requester_index;
        return 1;
    }
    return 0;
}

static int resolve_global_symbol_versioned(
    const ObjectGraph *graph, size_t requester_index, const char *name,
    size_t name_length,
    const SymbolVersionRequirement *version_requirement,
    uintptr_t *address) {
    if (requester_index >= graph->object_count || name_length == 0 ||
        name_length > MAXIMUM_SYMBOL_NAME_BYTES) {
        return 0;
    }
    const LoadedObject *requester = &graph->objects[requester_index];
    if (requester->dynamic.has_symbolic &&
        find_exported_symbol_versioned(requester, name, name_length,
                                       version_requirement, address)) {
        return 1;
    }
    for (size_t index = 0; index < graph->object_count; ++index) {
        if (index != requester_index &&
            find_exported_symbol_versioned(
                &graph->objects[index], name, name_length,
                version_requirement, address)) {
            return 1;
        }
    }
    if (!requester->dynamic.has_symbolic) {
        return find_exported_symbol_versioned(
            requester, name, name_length, version_requirement, address);
    }
    return 0;
}

static int apply_external_relocations(ObjectGraph *graph,
                                      size_t object_index,
                                      RelocationEvidence *evidence) {
    if (object_index >= graph->object_count) {
        return 0;
    }
    LoadedObject *consumer = &graph->objects[object_index];
    const Elf64Rela *relocations =
        (const Elf64Rela *)consumer->dynamic.jump_relocations;
    size_t count =
        consumer->dynamic.jump_relocation_size / sizeof(*relocations);
    uint32_t symbol_count = 0;
    if (count > MAXIMUM_RELOCATIONS ||
        !dynamic_symbol_count(consumer, &symbol_count)) {
        return 0;
    }
    const Elf64Symbol *symbols =
        (const Elf64Symbol *)consumer->dynamic.symbol_table;
    for (size_t index = 0; index < count; ++index) {
        uint32_t relocation_type =
            (uint32_t)relocations[index].information;
        uint32_t symbol_index =
            (uint32_t)(relocations[index].information >> 32);
        uintptr_t target = 0;
        if (relocation_type != RELOCATION_X86_64_JUMP_SLOT ||
            symbol_index == 0 || symbol_index >= symbol_count ||
            relocations[index].addend != 0 ||
            !checked_add(consumer->base, relocations[index].offset, &target) ||
            target % sizeof(uintptr_t) != 0 ||
            !mapped_range_contains(consumer->loads, consumer->load_count,
                                   target, sizeof(uintptr_t),
                                   PROGRAM_WRITABLE)) {
            return 0;
        }
        const Elf64Symbol *symbol = &symbols[symbol_index];
        const char *name = NULL;
        size_t name_length = 0;
        uintptr_t provider_symbol = 0;
        SymbolVersionRequirement version_requirement;
        uint8_t symbol_type = symbol->information & 0x0f;
        int tls_resolver_reference =
            is_tls_resolver_reference(consumer, symbol);
        if (symbol->section_index != SYMBOL_UNDEFINED ||
            (symbol_type != SYMBOL_FUNCTION && !tls_resolver_reference) ||
            (symbol->information >> 4) != SYMBOL_BIND_GLOBAL ||
            (symbol->other & 0x03) != SYMBOL_VISIBILITY_DEFAULT ||
            symbol->value != 0 || symbol->size != 0 ||
            !dynamic_symbol_name(consumer, symbol, &name, &name_length) ||
            is_tls_resolver_name(name, name_length) !=
                tls_resolver_reference ||
            !symbol_version_requirement(consumer, symbol_index,
                                        &version_requirement)) {
            return 0;
        }
        if (tls_resolver_reference) {
            if (version_requirement.explicit_version ||
                version_requirement.has_provider) {
                return 0;
            }
            provider_symbol = (uintptr_t)&arach_tls_get_addr;
        } else if (!resolve_global_symbol_versioned(
                       graph, object_index, name, name_length,
                       &version_requirement, &provider_symbol)) {
            return 0;
        }
        *(volatile uintptr_t *)target = provider_symbol;
        if (*(volatile const uintptr_t *)target != provider_symbol) {
            return 0;
        }
        ++evidence->external;
        if (version_requirement.explicit_version) {
            ++evidence->versioned;
        }
    }
    return 1;
}

static int relocate_graph(ObjectGraph *graph,
                          const StaticTlsLayout *tls_layout,
                          RelocationEvidence *evidence) {
    evidence->relative = 0;
    evidence->external = 0;
    evidence->tls = 0;
    evidence->versioned = 0;
    for (size_t index = 0; index < graph->relocation_count; ++index) {
        size_t object_index = graph->relocation_order[index];
        if (object_index >= graph->object_count ||
            !apply_object_relocations(graph, object_index, tls_layout,
                                      evidence)) {
            return 0;
        }
    }
    for (size_t index = 0; index < graph->relocation_count; ++index) {
        if (!apply_external_relocations(graph, graph->relocation_order[index],
                                        evidence)) {
            return 0;
        }
    }
    return 1;
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

static int record_opened_path(LoadedObject *object, const char *path,
                              size_t path_length, int from_runpath) {
    if (path_length > MAXIMUM_OBJECT_PATH_BYTES) {
        return 0;
    }
    for (size_t index = 0; index <= path_length; ++index) {
        object->path[index] = path[index];
    }
    object->path_length = path_length;
    object->loaded_from_runpath = from_runpath;
    return 1;
}

static int open_shared_object(const ObjectName *name,
                              const SearchPath *search_path,
                              LoadedObject *object, long *descriptor) {
    char path[MAXIMUM_OBJECT_PATH_BYTES + 1];
    if (search_path != NULL) {
        for (size_t index = 0; index < search_path->count; ++index) {
            size_t path_length = 0;
            if (!build_object_path_in_directory(
                    &search_path->directories[index], name, path,
                    sizeof(path), &path_length)) {
                return 0;
            }
            long result = syscall3(SYS_OPEN, (uintptr_t)path, O_RDONLY, 0);
            if (result >= 3) {
                if (!record_opened_path(object, path, path_length, 1)) {
                    (void)syscall3(SYS_CLOSE, (uint64_t)result, 0, 0);
                    return 0;
                }
                *descriptor = result;
                return 1;
            }
            if (result >= 0) {
                (void)syscall3(SYS_CLOSE, (uint64_t)result, 0, 0);
                return 0;
            }
            if (result != ERROR_NO_ENTRY) {
                return 0;
            }
        }
    }
    size_t path_length = 0;
    if (!build_object_path_in_directory(NULL, name, path, sizeof(path),
                                        &path_length)) {
        return 0;
    }
    long result = syscall3(SYS_OPEN, (uintptr_t)path, O_RDONLY, 0);
    if (result < 3) {
        if (result >= 0) {
            (void)syscall3(SYS_CLOSE, (uint64_t)result, 0, 0);
        }
        return 0;
    }
    if (!record_opened_path(object, path, path_length, 0)) {
        (void)syscall3(SYS_CLOSE, (uint64_t)result, 0, 0);
        return 0;
    }
    *descriptor = result;
    return 1;
}

static void load_shared_object(const ObjectName *name,
                               const SearchPath *search_path, uintptr_t base,
                               LoadedObject *object) {
    zero_bytes((uint8_t *)object, sizeof(*object));
    object->name = *name;
    long descriptor = -1;
    if (!open_shared_object(name, search_path, object, &descriptor)) {
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
    object->tls_program = NULL;
    object->load_count = 0;
    size_t load_count = 0;
    for (size_t index = 0; index < header->program_header_count; ++index) {
        const Elf64ProgramHeader *program = &headers[index];
        if (program->type != PROGRAM_LOAD) {
            if (program->type == PROGRAM_TLS) {
                if (object->tls_program != NULL) {
                    fail_with(shared_elf_failure,
                              sizeof(shared_elf_failure) - 1);
                }
                object->tls_program = program;
            } else if (program->type != PROGRAM_DYNAMIC) {
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
    if (object->tls_program != NULL) {
        const Elf64ProgramHeader *tls = object->tls_program;
        uintptr_t template_address = 0;
        if (tls->memory_size == 0 || tls->file_size > tls->memory_size ||
            tls->memory_size > MAXIMUM_STATIC_TLS_BYTES ||
            tls->file_size > SIZE_MAX || tls->memory_size > SIZE_MAX ||
            tls->flags != PROGRAM_READABLE ||
            !is_power_of_two(tls->alignment) ||
            tls->alignment > MAXIMUM_TLS_ALIGNMENT ||
            tls->virtual_address % tls->alignment !=
                tls->offset % tls->alignment ||
            tls->offset > (uint64_t)file_size ||
            tls->file_size > (uint64_t)file_size - tls->offset ||
            !tls_program_matches_load(object, tls) ||
            !checked_add(base, tls->virtual_address, &template_address) ||
            !mapped_range_contains(object->loads, object->load_count,
                                   template_address,
                                   (size_t)tls->memory_size,
                                   PROGRAM_READABLE)) {
            fail_with(shared_elf_failure, sizeof(shared_elf_failure) - 1);
        }
    }
    if (!parse_shared_dynamic(object) || !validate_dynamic_symbols(object)) {
        fail_with(shared_dynamic_failure,
                  sizeof(shared_dynamic_failure) - 1);
    }
}

static int load_graph_object(ObjectGraph *graph, const ObjectName *name,
                             const SearchPath *search_path,
                             size_t *object_index) {
    size_t existing = 0;
    if (graph_find_object(graph, name, &existing)) {
        *object_index = existing;
        return 1;
    }
    if (graph->object_count == MAXIMUM_LOADED_OBJECTS) {
        return 0;
    }
    size_t index = graph->object_count;
    uintptr_t base = 0;
    uint64_t offset = (uint64_t)index * (uint64_t)object_address_stride;
    if (!checked_add(first_object_base, offset, &base)) {
        return 0;
    }
    load_shared_object(name, search_path, base, &graph->objects[index]);
    ++graph->object_count;
    *object_index = index;
    return 1;
}

static int load_dependency_graph(const DependencyNames *roots,
                                 ObjectGraph *graph) {
    zero_bytes((uint8_t *)graph, sizeof(*graph));
    if (roots->count == 0 || roots->count > MAXIMUM_NEEDED_ENTRIES) {
        return 0;
    }
    for (size_t index = 0; index < roots->count; ++index) {
        size_t root_index = 0;
        if (!load_graph_object(graph, &roots->names[index], NULL,
                               &root_index) ||
            root_index != index) {
            return 0;
        }
    }
    for (size_t consumer_index = 0;
         consumer_index < graph->object_count; ++consumer_index) {
        LoadedObject *consumer = &graph->objects[consumer_index];
        consumer->dependency_count = 0;
        for (size_t dependency_index = 0;
             dependency_index < consumer->dynamic.needed_count;
             ++dependency_index) {
            ObjectName dependency_name;
            size_t provider_index = 0;
            const SearchPath *search_path =
                consumer->dynamic.has_runpath ? &consumer->dynamic.runpath
                                              : NULL;
            if (!object_dependency_name(consumer, dependency_index,
                                        &dependency_name) ||
                !load_graph_object(graph, &dependency_name, search_path,
                                   &provider_index) ||
                consumer->dependency_count == MAXIMUM_NEEDED_ENTRIES) {
                return 0;
            }
            for (size_t prior = 0; prior < consumer->dependency_count;
                 ++prior) {
                if (consumer->dependencies[prior] == provider_index) {
                    return 0;
                }
            }
            consumer->dependencies[consumer->dependency_count] =
                provider_index;
            ++consumer->dependency_count;
        }
    }
    return compute_relocation_order(graph);
}

static int seal_graph(const ObjectGraph *graph) {
    for (size_t index = 0; index < graph->relocation_count; ++index) {
        size_t object_index = graph->relocation_order[index];
        if (object_index >= graph->object_count ||
            !seal_shared_loads(&graph->objects[object_index])) {
            return 0;
        }
    }
    return 1;
}

static int call_initializer(const LoadedObject *object, uintptr_t address,
                            InitializerEvidence *evidence) {
    if (!mapped_range_contains(object->loads, object->load_count, address, 1,
                               PROGRAM_EXECUTABLE)) {
        return 0;
    }
    typedef void (*Initializer)(void);
    Initializer initializer = (Initializer)address;
    initializer();
    ++evidence->calls;
    return 1;
}

static int run_initializers(const ObjectGraph *graph,
                            InitializerEvidence *evidence) {
    evidence->calls = 0;
    for (size_t index = 0; index < graph->relocation_count; ++index) {
        size_t object_index = graph->relocation_order[index];
        if (object_index >= graph->object_count) {
            return 0;
        }
        const LoadedObject *object = &graph->objects[object_index];
        if (object->dynamic.has_init_function &&
            !call_initializer(object, object->dynamic.init_function,
                              evidence)) {
            return 0;
        }
        const uintptr_t *array =
            (const uintptr_t *)object->dynamic.init_array;
        size_t count = object->dynamic.init_array_size / sizeof(*array);
        for (size_t initializer = 0; initializer < count; ++initializer) {
            if (!call_initializer(object, array[initializer], evidence)) {
                return 0;
            }
        }
    }
    return 1;
}

static int prepare_finalization_plan(const ObjectGraph *graph,
                                     uintptr_t tls_instance,
                                     FinalizationPlan *plan) {
    zero_bytes((uint8_t *)plan, sizeof(*plan));
    if (graph->relocation_count > MAXIMUM_LOADED_OBJECTS) {
        return 0;
    }
    for (size_t index = 0; index < graph->relocation_count; ++index) {
        size_t object_index = graph->relocation_order[index];
        if (object_index >= graph->object_count) {
            return 0;
        }
        const LoadedObject *object = &graph->objects[object_index];
        FinalizerObject *finalizer = &plan->objects[index];
        if (object->dynamic.has_fini_function) {
            if (!mapped_range_contains(
                    object->loads, object->load_count,
                    object->dynamic.fini_function, 1,
                    PROGRAM_EXECUTABLE)) {
                return 0;
            }
            finalizer->fini_function = object->dynamic.fini_function;
            ++plan->expected_calls;
        }
        const uintptr_t *array =
            (const uintptr_t *)object->dynamic.fini_array;
        size_t count = object->dynamic.fini_array_size / sizeof(*array);
        if (count > MAXIMUM_INITIALIZERS) {
            return 0;
        }
        for (size_t entry = 0; entry < count; ++entry) {
            if (!mapped_range_contains(object->loads, object->load_count,
                                       array[entry], 1,
                                       PROGRAM_EXECUTABLE)) {
                return 0;
            }
            finalizer->fini_array[entry] = array[entry];
            ++plan->expected_calls;
        }
        finalizer->fini_array_count = count;
    }
    plan->object_count = graph->relocation_count;
    plan->tls_instance = tls_instance;
    plan->armed = 1;
    return 1;
}

static int run_finalizers(FinalizationPlan *plan,
                          FinalizerEvidence *evidence) {
    evidence->calls = 0;
    if (!plan->armed || plan->object_count > MAXIMUM_LOADED_OBJECTS) {
        return 0;
    }
    plan->armed = 0;
    typedef void (*Finalizer)(void);
    for (size_t remaining = plan->object_count; remaining > 0;
         --remaining) {
        const FinalizerObject *object = &plan->objects[remaining - 1];
        if (object->fini_array_count > MAXIMUM_INITIALIZERS) {
            return 0;
        }
        for (size_t entries = object->fini_array_count; entries > 0;
             --entries) {
            Finalizer finalizer =
                (Finalizer)object->fini_array[entries - 1];
            finalizer();
            ++evidence->calls;
        }
        if (object->fini_function != 0) {
            Finalizer finalizer = (Finalizer)object->fini_function;
            finalizer();
            ++evidence->calls;
        }
    }
    return evidence->calls == plan->expected_calls;
}

void arach_runtime_linker_finalize(void) {
    FinalizerEvidence evidence;
    if (!run_finalizers(&finalization_plan, &evidence) ||
        evidence.calls != 8 || finalization_plan.tls_instance == 0 ||
        *(volatile const uint64_t *)finalization_plan.tls_instance !=
            UINT64_C(0xdddddddddddddddd)) {
        (void)write_marker(shared_finalization_failure,
                           sizeof(shared_finalization_failure) - 1);
        fail();
    }
    if (!write_marker(finalization_marker,
                      sizeof(finalization_marker) - 1)) {
        fail();
    }
}

static int release_graph(const ObjectGraph *graph) {
    for (size_t index = 0; index < graph->object_count; ++index) {
        if (!release_shared_snapshot(&graph->objects[index])) {
            return 0;
        }
    }
    return 1;
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

    DependencyNames roots;
    uintptr_t main_base = 0;
    if (!discover_main_dependencies(
            (const Elf64ProgramHeader *)program_headers,
            program_header_count, &main_base, &roots) ||
        main_base == 0 || roots.count != 1 ||
        !object_name_equals_literal(&roots.names[0], expected_needed,
                                    sizeof(expected_needed) - 1) ||
        !write_marker(needed_marker, sizeof(needed_marker) - 1)) {
        fail_with(dependency_failure, sizeof(dependency_failure) - 1);
    }
    ObjectGraph graph;
    if (!load_dependency_graph(&roots, &graph) ||
        !verify_probe_graph(&graph) ||
        !write_marker(graph_marker, sizeof(graph_marker) - 1) ||
        !write_marker(multi_object_marker,
                      sizeof(multi_object_marker) - 1)) {
        fail_with(shared_graph_failure, sizeof(shared_graph_failure) - 1);
    }
    if (!verify_probe_runpaths(&graph) ||
        !write_marker(runpath_marker, sizeof(runpath_marker) - 1)) {
        fail_with(shared_runpath_failure,
                  sizeof(shared_runpath_failure) - 1);
    }
    StaticTlsLayout tls_layout;
    if (!install_static_tls(&graph, &tls_layout) ||
        tls_layout.object_count != 1 || tls_layout.payload_size != 8 ||
        tls_layout.dtv_count != 5 || tls_layout.dtv == 0 ||
        graph.objects[3].tls_instance == 0 ||
        graph.objects[3].tls_instance + sizeof(uint64_t) !=
            tls_layout.thread_pointer ||
        ((const DynamicTlsEntry *)tls_layout.dtv)[4].address !=
            graph.objects[3].tls_instance ||
        ((const DynamicTlsEntry *)tls_layout.dtv)[4].size != sizeof(uint64_t)) {
        fail_with(shared_tls_failure, sizeof(shared_tls_failure) - 1);
    }
    RelocationEvidence evidence;
    if (!relocate_graph(&graph, &tls_layout, &evidence) ||
        evidence.relative != 9 || evidence.external != 8 ||
        evidence.tls != 3 ||
        !write_marker(relocation_marker, sizeof(relocation_marker) - 1)) {
        fail_with(shared_relocation_failure,
                  sizeof(shared_relocation_failure) - 1);
    }
    if (!write_marker(symbol_scope_marker,
                      sizeof(symbol_scope_marker) - 1)) {
        fail_with(shared_external_failure,
                  sizeof(shared_external_failure) - 1);
    }
    if (evidence.versioned != 10 ||
        !write_marker(version_marker, sizeof(version_marker) - 1)) {
        fail_with(shared_version_failure,
                  sizeof(shared_version_failure) - 1);
    }
    uintptr_t shared_symbol = 0;
    if (!find_exported_symbol(&graph.objects[0], expected_symbol,
                              sizeof(expected_symbol) - 1,
                              &shared_symbol)) {
        fail_with(shared_symbol_failure, sizeof(shared_symbol_failure) - 1);
    }
    if (!seal_graph(&graph)) {
        fail_with(shared_map_failure, sizeof(shared_map_failure) - 1);
    }
    InitializerEvidence initializer_evidence;
    if (!run_initializers(&graph, &initializer_evidence) ||
        initializer_evidence.calls != 4 ||
        *(volatile const uint64_t *)graph.objects[3].tls_instance !=
            UINT64_C(0x1111111111111111)) {
        fail_with(shared_initializer_failure,
                  sizeof(shared_initializer_failure) - 1);
    }
    if (!prepare_finalization_plan(
            &graph, graph.objects[3].tls_instance, &finalization_plan) ||
        finalization_plan.object_count != 4 ||
        finalization_plan.expected_calls != 8) {
        fail_with(shared_finalization_failure,
                  sizeof(shared_finalization_failure) - 1);
    }
    if (!release_graph(&graph)) {
        fail_with(shared_map_failure, sizeof(shared_map_failure) - 1);
    }
    typedef uint64_t (*SharedProbe)(uint64_t);
    SharedProbe shared_probe = (SharedProbe)shared_symbol;
    const uint64_t input = UINT64_C(0x1122334455667788);
    const uint64_t core = UINT64_C(0x1020304050607080) +
                          UINT64_C(0x1111111111111111) +
                          UINT64_C(0x2222222222222222);
    const uint64_t provider =
        input + UINT64_C(0x1111222233334444) + core +
        UINT64_C(0x3333333333333333);
    const uint64_t observer =
        (input ^ UINT64_C(0x0f0ff0f05a5aa5a5)) + core +
        UINT64_C(0x4444444444444444);
    const uint64_t expected =
        provider ^ observer ^ UINT64_C(0xa5a55a5af0f00f0f) ^
        UINT64_C(0x5555555555555555);
    if (shared_probe(input) != expected) {
        fail_with(shared_call_failure, sizeof(shared_call_failure) - 1);
    }
    if (!write_marker(static_tls_marker, sizeof(static_tls_marker) - 1)) {
        fail_with(shared_tls_failure, sizeof(shared_tls_failure) - 1);
    }
    if (!dynamic_tls_state.armed || dynamic_tls_state.calls != 3 ||
        !write_marker(dynamic_tls_marker, sizeof(dynamic_tls_marker) - 1)) {
        fail_with(shared_dynamic_tls_failure,
                  sizeof(shared_dynamic_tls_failure) - 1);
    }
    if (!write_marker(initializer_marker, sizeof(initializer_marker) - 1)) {
        fail_with(shared_initializer_failure,
                  sizeof(shared_initializer_failure) - 1);
    }
    if (!write_marker(external_marker, sizeof(external_marker) - 1)) {
        fail_with(shared_call_failure, sizeof(shared_call_failure) - 1);
    }
    if (!write_marker(pass_marker, sizeof(pass_marker) - 1)) {
        fail();
    }
    return executable_entry;
}
