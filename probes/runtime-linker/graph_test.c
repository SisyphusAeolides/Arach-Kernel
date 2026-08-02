#include "runtime_linker.c"

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[32];
} SymbolFixture;

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[32];
    Elf64Rela relocations[3];
    uint64_t targets[3];
} TlsConsumerFixture;

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[32];
    uint64_t storage[2];
} TlsProviderFixture;

typedef struct {
    Elf64VersionDefinition definition;
    Elf64VersionDefinitionAuxiliary auxiliary;
} VersionDefinitionFixture;

typedef struct {
    Elf64VersionRequirement requirement;
    Elf64VersionRequirementAuxiliary auxiliary;
} VersionRequirementFixture;

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[64];
    uint16_t versions[2];
    VersionDefinitionFixture definitions[2];
} VersionProviderFixture;

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[64];
    uint16_t versions[2];
    VersionRequirementFixture requirements[1];
} VersionConsumerFixture;

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[32];
    uint16_t versions[2];
} TlsResolverVersionFixture;

static size_t initializer_sequence[4];
static size_t initializer_count;
static size_t finalizer_sequence[8];
static size_t finalizer_count;

static uintptr_t first_definition(uintptr_t value);
static uintptr_t second_definition(uintptr_t value);
static int set_name(ObjectName *name, const char *value, size_t length);
static void prepare_symbol_object(LoadedObject *object, SymbolFixture *fixture,
                                  uintptr_t definition);
static int test_names(void);
static int test_graph_order(void);
static int test_cycle_rejection(void);
static int test_symbol_scope(void);
static int test_symbol_versions(void);
static int test_tls_resolver_reference(void);
static int test_static_tls_layout(void);
static int test_dynamic_tls_index(void);
static int test_tls_relocation(void);
static int test_initializer_order(void);
static int test_finalizer_order(void);
int main(void);

static uintptr_t first_definition(uintptr_t value) { return value + 1; }

static uintptr_t second_definition(uintptr_t value) { return value + 2; }

static void initializer_root(void) {
    initializer_sequence[initializer_count++] = 0;
}

static void initializer_provider(void) {
    initializer_sequence[initializer_count++] = 1;
}

static void initializer_observer(void) {
    initializer_sequence[initializer_count++] = 2;
}

static void initializer_core(void) {
    initializer_sequence[initializer_count++] = 3;
}

static void finalizer_root_first(void) {
    finalizer_sequence[finalizer_count++] = 0;
}

static void finalizer_root_second(void) {
    finalizer_sequence[finalizer_count++] = 1;
}

static void finalizer_root_function(void) {
    finalizer_sequence[finalizer_count++] = 2;
}

static void finalizer_observer_array(void) {
    finalizer_sequence[finalizer_count++] = 3;
}

static void finalizer_observer_function(void) {
    finalizer_sequence[finalizer_count++] = 4;
}

static void finalizer_provider_array(void) {
    finalizer_sequence[finalizer_count++] = 5;
}

static void finalizer_provider_function(void) {
    finalizer_sequence[finalizer_count++] = 6;
}

static void finalizer_core_function(void) {
    finalizer_sequence[finalizer_count++] = 7;
}

static int set_name(ObjectName *name, const char *value, size_t length) {
    return copy_object_name(value, length + 1, name);
}

static int copy_fixture_string(char *strings, size_t capacity, size_t offset,
                               const char *value, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return 0;
    }
    for (size_t index = 0; index < length; ++index) {
        strings[offset + index] = value[index];
    }
    return 1;
}

static void prepare_symbol_object(LoadedObject *object, SymbolFixture *fixture,
                                  uintptr_t definition) {
    zero_bytes((uint8_t *)object, sizeof(*object));
    zero_bytes((uint8_t *)fixture, sizeof(*fixture));
    fixture->hash[0] = 1;
    fixture->hash[1] = 2;
    fixture->strings[0] = '\0';
    const char symbol_name[] = "shared_definition";
    for (size_t index = 0; index < sizeof(symbol_name); ++index) {
        fixture->strings[index + 1] = symbol_name[index];
    }
    fixture->symbols[1].name = 1;
    fixture->symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_FUNCTION);
    fixture->symbols[1].other = SYMBOL_VISIBILITY_DEFAULT;
    fixture->symbols[1].section_index = 1;
    fixture->symbols[1].value = definition;
    fixture->symbols[1].size = 1;
    object->dynamic.hash = (uintptr_t)&fixture->hash[0];
    object->dynamic.symbol_table = (uintptr_t)&fixture->symbols[0];
    object->dynamic.string_table = (uintptr_t)&fixture->strings[0];
    object->dynamic.string_size = sizeof(symbol_name) + 1;
    object->loads[0].address = (uintptr_t)fixture;
    object->loads[0].memory_size = sizeof(*fixture);
    object->loads[0].mapping_size = sizeof(*fixture);
    object->loads[0].flags = PROGRAM_READABLE;
    object->loads[1].address = definition;
    object->loads[1].memory_size = 1;
    object->loads[1].mapping_size = 1;
    object->loads[1].flags = PROGRAM_READABLE | PROGRAM_EXECUTABLE;
    object->load_count = 2;
}

static int test_names(void) {
    ObjectName name;
    char too_long[MAXIMUM_OBJECT_NAME_BYTES + 2];
    for (size_t index = 0; index < sizeof(too_long) - 1; ++index) {
        too_long[index] = 'a';
    }
    too_long[sizeof(too_long) - 1] = '\0';
    return copy_object_name("libc.so.6", sizeof("libc.so.6"), &name) &&
           object_name_equals_literal(&name, "libc.so.6",
                                      sizeof("libc.so.6") - 1) &&
           !copy_object_name("../escape.so", sizeof("../escape.so"), &name) &&
           !copy_object_name("/absolute.so", sizeof("/absolute.so"), &name) &&
           !copy_object_name(".hidden.so", sizeof(".hidden.so"), &name) &&
           !copy_object_name("trailing.", sizeof("trailing."), &name) &&
           !copy_object_name(too_long, sizeof(too_long), &name);
}

static int test_graph_order(void) {
    ObjectGraph graph;
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    graph.object_count = 4;
    if (!set_name(&graph.objects[0].name, expected_needed,
                  sizeof(expected_needed) - 1) ||
        !set_name(&graph.objects[1].name, expected_provider,
                  sizeof(expected_provider) - 1) ||
        !set_name(&graph.objects[2].name, expected_observer,
                  sizeof(expected_observer) - 1) ||
        !set_name(&graph.objects[3].name, expected_core,
                  sizeof(expected_core) - 1)) {
        return 0;
    }
    graph.objects[0].dependencies[0] = 1;
    graph.objects[0].dependencies[1] = 2;
    graph.objects[0].dependency_count = 2;
    graph.objects[1].dependencies[0] = 3;
    graph.objects[1].dependency_count = 1;
    graph.objects[2].dependencies[0] = 3;
    graph.objects[2].dependency_count = 1;
    size_t core_index = 0;
    return graph_find_object(&graph, &graph.objects[3].name, &core_index) &&
           core_index == 3 && compute_relocation_order(&graph) &&
           verify_probe_graph(&graph) && graph.relocation_order[0] == 3 &&
           graph.relocation_order[1] == 1 &&
           graph.relocation_order[2] == 2 &&
           graph.relocation_order[3] == 0;
}

static int test_cycle_rejection(void) {
    ObjectGraph graph;
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    graph.object_count = 2;
    graph.objects[0].dependencies[0] = 1;
    graph.objects[0].dependency_count = 1;
    graph.objects[1].dependencies[0] = 0;
    graph.objects[1].dependency_count = 1;
    if (compute_relocation_order(&graph)) {
        return 0;
    }
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    graph.object_count = 1;
    graph.objects[0].dependencies[0] = MAXIMUM_LOADED_OBJECTS;
    graph.objects[0].dependency_count = 1;
    return !compute_relocation_order(&graph);
}

static int test_symbol_scope(void) {
    ObjectGraph graph;
    SymbolFixture first_fixture;
    SymbolFixture second_fixture;
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    graph.object_count = 3;
    prepare_symbol_object(&graph.objects[0], &first_fixture,
                          (uintptr_t)&first_definition);
    prepare_symbol_object(&graph.objects[1], &second_fixture,
                          (uintptr_t)&second_definition);
    uintptr_t address = 0;
    SymbolVersionRequirement version_requirement;
    zero_bytes((uint8_t *)&version_requirement,
               sizeof(version_requirement));
    return resolve_global_symbol_versioned(
               &graph, 2, "shared_definition",
               sizeof("shared_definition") - 1, &version_requirement,
               &address) &&
           address == (uintptr_t)&first_definition;
}

static int prepare_version_provider(LoadedObject *object,
                                    VersionProviderFixture *fixture,
                                    uintptr_t definition) {
    const char soname[] = "libprovider.so";
    const char version[] = "VER_1";
    const char symbol_name[] = "shared_definition";
    zero_bytes((uint8_t *)object, sizeof(*object));
    zero_bytes((uint8_t *)fixture, sizeof(*fixture));
    if (!set_name(&object->name, soname, sizeof(soname) - 1) ||
        !copy_fixture_string(fixture->strings, sizeof(fixture->strings), 1,
                             soname, sizeof(soname)) ||
        !copy_fixture_string(fixture->strings, sizeof(fixture->strings), 16,
                             version, sizeof(version)) ||
        !copy_fixture_string(fixture->strings, sizeof(fixture->strings), 22,
                             symbol_name, sizeof(symbol_name))) {
        return 0;
    }
    fixture->hash[0] = 1;
    fixture->hash[1] = 2;
    fixture->symbols[1].name = 22;
    fixture->symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_FUNCTION);
    fixture->symbols[1].other = SYMBOL_VISIBILITY_DEFAULT;
    fixture->symbols[1].section_index = 1;
    fixture->symbols[1].value = definition;
    fixture->symbols[1].size = 1;
    fixture->versions[1] = 2;
    fixture->definitions[0].definition.version = VERSION_CURRENT;
    fixture->definitions[0].definition.flags = VERSION_FLAG_BASE;
    fixture->definitions[0].definition.index = 1;
    fixture->definitions[0].definition.auxiliary_count = 1;
    fixture->definitions[0].definition.hash =
        version_name_hash(soname, sizeof(soname) - 1);
    fixture->definitions[0].definition.auxiliary =
        sizeof(Elf64VersionDefinition);
    fixture->definitions[0].definition.next =
        sizeof(VersionDefinitionFixture);
    fixture->definitions[0].auxiliary.name = 1;
    fixture->definitions[1].definition.version = VERSION_CURRENT;
    fixture->definitions[1].definition.index = 2;
    fixture->definitions[1].definition.auxiliary_count = 1;
    fixture->definitions[1].definition.hash =
        version_name_hash(version, sizeof(version) - 1);
    fixture->definitions[1].definition.auxiliary =
        sizeof(Elf64VersionDefinition);
    fixture->definitions[1].auxiliary.name = 16;
    object->dynamic.hash = (uintptr_t)&fixture->hash[0];
    object->dynamic.symbol_table = (uintptr_t)&fixture->symbols[0];
    object->dynamic.string_table = (uintptr_t)&fixture->strings[0];
    object->dynamic.string_size = sizeof(fixture->strings);
    object->dynamic.version_symbols = (uintptr_t)&fixture->versions[0];
    object->dynamic.version_definitions =
        (uintptr_t)&fixture->definitions[0];
    object->dynamic.version_definition_count = 2;
    object->dynamic.has_version_symbols = 1;
    object->dynamic.has_version_definitions = 1;
    object->dynamic.has_version_definition_count = 1;
    object->loads[0].address = (uintptr_t)fixture;
    object->loads[0].memory_size = sizeof(*fixture);
    object->loads[0].mapping_size = sizeof(*fixture);
    object->loads[0].flags = PROGRAM_READABLE;
    object->loads[1].address = definition;
    object->loads[1].memory_size = 1;
    object->loads[1].mapping_size = 1;
    object->loads[1].flags = PROGRAM_READABLE | PROGRAM_EXECUTABLE;
    object->load_count = 2;
    return 1;
}

static int prepare_version_consumer(LoadedObject *object,
                                    VersionConsumerFixture *fixture) {
    const char provider[] = "libprovider.so";
    const char version[] = "VER_1";
    const char symbol_name[] = "shared_definition";
    zero_bytes((uint8_t *)object, sizeof(*object));
    zero_bytes((uint8_t *)fixture, sizeof(*fixture));
    if (!copy_fixture_string(fixture->strings, sizeof(fixture->strings), 1,
                             provider, sizeof(provider)) ||
        !copy_fixture_string(fixture->strings, sizeof(fixture->strings), 16,
                             version, sizeof(version)) ||
        !copy_fixture_string(fixture->strings, sizeof(fixture->strings), 22,
                             symbol_name, sizeof(symbol_name))) {
        return 0;
    }
    fixture->hash[0] = 1;
    fixture->hash[1] = 2;
    fixture->symbols[1].name = 22;
    fixture->symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_FUNCTION);
    fixture->symbols[1].other = SYMBOL_VISIBILITY_DEFAULT;
    fixture->symbols[1].section_index = SYMBOL_UNDEFINED;
    fixture->versions[1] = 2;
    fixture->requirements[0].requirement.version = VERSION_CURRENT;
    fixture->requirements[0].requirement.auxiliary_count = 1;
    fixture->requirements[0].requirement.file = 1;
    fixture->requirements[0].requirement.auxiliary =
        sizeof(Elf64VersionRequirement);
    fixture->requirements[0].auxiliary.hash =
        version_name_hash(version, sizeof(version) - 1);
    fixture->requirements[0].auxiliary.other = 2;
    fixture->requirements[0].auxiliary.name = 16;
    object->dynamic.hash = (uintptr_t)&fixture->hash[0];
    object->dynamic.symbol_table = (uintptr_t)&fixture->symbols[0];
    object->dynamic.string_table = (uintptr_t)&fixture->strings[0];
    object->dynamic.string_size = sizeof(fixture->strings);
    object->dynamic.needed_offsets[0] = 1;
    object->dynamic.needed_count = 1;
    object->dynamic.version_symbols = (uintptr_t)&fixture->versions[0];
    object->dynamic.version_requirements =
        (uintptr_t)&fixture->requirements[0];
    object->dynamic.version_requirement_count = 1;
    object->dynamic.has_version_symbols = 1;
    object->dynamic.has_version_requirements = 1;
    object->dynamic.has_version_requirement_count = 1;
    object->loads[0].address = (uintptr_t)fixture;
    object->loads[0].memory_size = sizeof(*fixture);
    object->loads[0].mapping_size = sizeof(*fixture);
    object->loads[0].flags = PROGRAM_READABLE;
    object->load_count = 1;
    return 1;
}

static int test_symbol_versions(void) {
    ObjectGraph graph;
    VersionConsumerFixture consumer_fixture;
    VersionProviderFixture provider_fixture;
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    graph.object_count = 2;
    if (!prepare_version_consumer(&graph.objects[0], &consumer_fixture) ||
        !prepare_version_provider(&graph.objects[1], &provider_fixture,
                                  (uintptr_t)&first_definition) ||
        !validate_dynamic_symbols(&graph.objects[0]) ||
        !validate_dynamic_symbols(&graph.objects[1])) {
        return 0;
    }
    SymbolVersionRequirement requirement;
    uintptr_t address = 0;
    if (!symbol_version_requirement(&graph.objects[0], 1, &requirement) ||
        !requirement.explicit_version || !requirement.has_provider ||
        !resolve_global_symbol_versioned(
            &graph, 0, "shared_definition",
            sizeof("shared_definition") - 1, &requirement, &address) ||
        address != (uintptr_t)&first_definition) {
        return 0;
    }
    ObjectName wrong_provider;
    if (!set_name(&wrong_provider, "libwrong.so",
                  sizeof("libwrong.so") - 1)) {
        return 0;
    }
    requirement.provider = wrong_provider;
    if (resolve_global_symbol_versioned(
            &graph, 0, "shared_definition",
            sizeof("shared_definition") - 1, &requirement, &address)) {
        return 0;
    }
    if (!set_name(&requirement.provider, "libprovider.so",
                  sizeof("libprovider.so") - 1)) {
        return 0;
    }
    provider_fixture.versions[1] = VERSION_INDEX_HIDDEN | 2;
    if (!resolve_global_symbol_versioned(
            &graph, 0, "shared_definition",
            sizeof("shared_definition") - 1, &requirement, &address)) {
        return 0;
    }
    SymbolVersionRequirement unversioned;
    zero_bytes((uint8_t *)&unversioned, sizeof(unversioned));
    if (resolve_global_symbol_versioned(
            &graph, 0, "shared_definition",
            sizeof("shared_definition") - 1, &unversioned, &address)) {
        return 0;
    }
    provider_fixture.versions[1] = 2;
    consumer_fixture.requirements[0].auxiliary.hash ^= 1;
    return !validate_symbol_versions(&graph.objects[0], 2);
}

static int test_tls_resolver_reference(void) {
    LoadedObject object;
    TlsResolverVersionFixture fixture;
    const char symbol_name[] = "__tls_get_addr";
    zero_bytes((uint8_t *)&object, sizeof(object));
    zero_bytes((uint8_t *)&fixture, sizeof(fixture));
    if (!copy_fixture_string(fixture.strings, sizeof(fixture.strings), 1,
                             symbol_name, sizeof(symbol_name))) {
        return 0;
    }
    fixture.hash[0] = 1;
    fixture.hash[1] = 2;
    fixture.symbols[1].name = 1;
    fixture.symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_NO_TYPE);
    fixture.symbols[1].other = SYMBOL_VISIBILITY_DEFAULT;
    fixture.symbols[1].section_index = SYMBOL_UNDEFINED;
    fixture.versions[1] = VERSION_INDEX_LOCAL;
    object.dynamic.hash = (uintptr_t)&fixture.hash[0];
    object.dynamic.symbol_table = (uintptr_t)&fixture.symbols[0];
    object.dynamic.string_table = (uintptr_t)&fixture.strings[0];
    object.dynamic.string_size = sizeof(symbol_name) + 1;
    object.dynamic.version_symbols = (uintptr_t)&fixture.versions[0];
    object.dynamic.has_version_symbols = 1;
    object.loads[0].address = (uintptr_t)&fixture;
    object.loads[0].memory_size = sizeof(fixture);
    object.loads[0].mapping_size = sizeof(fixture);
    object.loads[0].flags = PROGRAM_READABLE;
    object.load_count = 1;
    SymbolVersionRequirement requirement;
    if (!validate_dynamic_symbols(&object) ||
        !symbol_version_requirement(&object, 1, &requirement) ||
        requirement.explicit_version || requirement.has_provider) {
        return 0;
    }
    fixture.versions[1] = VERSION_INDEX_HIDDEN | VERSION_INDEX_LOCAL;
    if (validate_symbol_versions(&object, 2) ||
        symbol_version_requirement(&object, 1, &requirement)) {
        return 0;
    }
    fixture.versions[1] = VERSION_INDEX_LOCAL;
    fixture.symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_FUNCTION);
    if (validate_symbol_versions(&object, 2)) {
        return 0;
    }
    fixture.versions[1] = VERSION_INDEX_GLOBAL;
    if (validate_dynamic_symbols(&object)) {
        return 0;
    }
    fixture.versions[1] = VERSION_INDEX_LOCAL;
    fixture.symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_NO_TYPE);
    fixture.strings[1] = 'x';
    return !validate_symbol_versions(&object, 2);
}

static int test_static_tls_layout(void) {
    ObjectGraph graph;
    StaticTlsLayout layout;
    Elf64ProgramHeader first;
    Elf64ProgramHeader second;
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    zero_bytes((uint8_t *)&first, sizeof(first));
    zero_bytes((uint8_t *)&second, sizeof(second));
    graph.object_count = 4;
    first.type = PROGRAM_TLS;
    first.file_size = 8;
    first.memory_size = 8;
    first.alignment = 8;
    second.type = PROGRAM_TLS;
    second.file_size = 8;
    second.memory_size = 24;
    second.alignment = 16;
    graph.objects[1].tls_program = &first;
    graph.objects[3].tls_program = &second;
    if (!plan_static_tls(&graph, &layout) || layout.object_count != 2 ||
        layout.payload_size != 48 || layout.mapping_size != PAGE_SIZE ||
        layout.dtv_offset != 64 || layout.dtv_count != 5 ||
        graph.objects[1].tls_offset != 0 ||
        graph.objects[1].tls_module_id != 2 ||
        graph.objects[3].tls_offset != 16 ||
        graph.objects[3].tls_module_id != 4) {
        return 0;
    }
    second.alignment = 3;
    return !plan_static_tls(&graph, &layout);
}

static int test_dynamic_tls_index(void) {
    DynamicTlsEntry dtv[5];
    DynamicTlsIndex index;
    uint64_t storage[2] = {UINT64_C(0x1111111111111111),
                           UINT64_C(0x2222222222222222)};
    uintptr_t address = 0;
    zero_bytes((uint8_t *)&dtv, sizeof(dtv));
    zero_bytes((uint8_t *)&index, sizeof(index));
    dtv[0].address = 4;
    dtv[0].size = 1;
    dtv[4].address = (uintptr_t)&storage[0];
    dtv[4].size = sizeof(storage);
    index.module = 4;
    index.offset = sizeof(storage[0]);
    if (!resolve_dynamic_tls_index(dtv, 5, &index, &address) ||
        address != (uintptr_t)&storage[1] ||
        *(const uint64_t *)address != storage[1]) {
        return 0;
    }
    index.offset = sizeof(storage);
    if (resolve_dynamic_tls_index(dtv, 5, &index, &address)) {
        return 0;
    }
    index.offset = 0;
    index.module = 3;
    if (resolve_dynamic_tls_index(dtv, 5, &index, &address)) {
        return 0;
    }
    index.module = 5;
    if (resolve_dynamic_tls_index(dtv, 5, &index, &address)) {
        return 0;
    }
    index.module = 4;
    dtv[0].address = 3;
    return !resolve_dynamic_tls_index(dtv, 5, &index, &address);
}

static void prepare_tls_hash(uint32_t *hash, Elf64Symbol *symbols,
                             char *strings, uint16_t section_index,
                             uint64_t symbol_size) {
    zero_bytes((uint8_t *)hash, 5 * sizeof(*hash));
    zero_bytes((uint8_t *)symbols, 2 * sizeof(*symbols));
    zero_bytes((uint8_t *)strings, 32);
    hash[0] = 1;
    hash[1] = 2;
    hash[2] = 1;
    const char name[] = "shared_tls";
    for (size_t index = 0; index < sizeof(name); ++index) {
        strings[index + 1] = name[index];
    }
    symbols[1].name = 1;
    symbols[1].information =
        (uint8_t)((SYMBOL_BIND_GLOBAL << 4) | SYMBOL_TLS);
    symbols[1].other = SYMBOL_VISIBILITY_DEFAULT;
    symbols[1].section_index = section_index;
    symbols[1].size = symbol_size;
}

static int test_tls_relocation(void) {
    ObjectGraph graph;
    TlsConsumerFixture consumer;
    TlsProviderFixture provider;
    Elf64ProgramHeader tls_program;
    StaticTlsLayout layout;
    RelocationEvidence evidence;
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    zero_bytes((uint8_t *)&consumer, sizeof(consumer));
    zero_bytes((uint8_t *)&provider, sizeof(provider));
    zero_bytes((uint8_t *)&tls_program, sizeof(tls_program));
    zero_bytes((uint8_t *)&layout, sizeof(layout));
    zero_bytes((uint8_t *)&evidence, sizeof(evidence));
    graph.object_count = 2;
    prepare_tls_hash(consumer.hash, consumer.symbols, consumer.strings,
                     SYMBOL_UNDEFINED, 0);
    prepare_tls_hash(provider.hash, provider.symbols, provider.strings, 1,
                     sizeof(provider.storage[1]));
    provider.symbols[1].value = sizeof(provider.storage[0]);
    const uint32_t types[3] = {
        RELOCATION_X86_64_DTPMOD64,
        RELOCATION_X86_64_DTPOFF64,
        RELOCATION_X86_64_TPOFF64,
    };
    for (size_t index = 0; index < 3; ++index) {
        consumer.relocations[index].offset =
            offsetof(TlsConsumerFixture, targets) +
            index * sizeof(consumer.targets[0]);
        consumer.relocations[index].information =
            (UINT64_C(1) << 32) | types[index];
    }
    graph.objects[0].base = (uintptr_t)&consumer;
    graph.objects[0].dynamic.hash = (uintptr_t)&consumer.hash[0];
    graph.objects[0].dynamic.symbol_table =
        (uintptr_t)&consumer.symbols[0];
    graph.objects[0].dynamic.string_table =
        (uintptr_t)&consumer.strings[0];
    graph.objects[0].dynamic.string_size = sizeof(consumer.strings);
    graph.objects[0].dynamic.relocations =
        (uintptr_t)&consumer.relocations[0];
    graph.objects[0].dynamic.relocation_size = sizeof(consumer.relocations);
    graph.objects[0].loads[0].address = (uintptr_t)&consumer;
    graph.objects[0].loads[0].memory_size = sizeof(consumer);
    graph.objects[0].loads[0].mapping_size = sizeof(consumer);
    graph.objects[0].loads[0].flags = PROGRAM_READABLE | PROGRAM_WRITABLE;
    graph.objects[0].load_count = 1;

    tls_program.type = PROGRAM_TLS;
    tls_program.file_size = sizeof(provider.storage);
    tls_program.memory_size = sizeof(provider.storage);
    tls_program.alignment = sizeof(provider.storage);
    graph.objects[1].dynamic.hash = (uintptr_t)&provider.hash[0];
    graph.objects[1].dynamic.symbol_table =
        (uintptr_t)&provider.symbols[0];
    graph.objects[1].dynamic.string_table =
        (uintptr_t)&provider.strings[0];
    graph.objects[1].dynamic.string_size = sizeof(provider.strings);
    graph.objects[1].tls_program = &tls_program;
    graph.objects[1].tls_instance = (uintptr_t)&provider.storage[0];
    graph.objects[1].tls_module_id = 2;
    graph.objects[1].loads[0].address = (uintptr_t)&provider;
    graph.objects[1].loads[0].memory_size = sizeof(provider);
    graph.objects[1].loads[0].mapping_size = sizeof(provider);
    graph.objects[1].loads[0].flags = PROGRAM_READABLE | PROGRAM_WRITABLE;
    graph.objects[1].load_count = 1;
    layout.thread_pointer = (uintptr_t)&provider.storage[0] +
                            sizeof(provider.storage);
    if (!apply_object_relocations(&graph, 0, &layout, &evidence) ||
        consumer.targets[0] != 2 || consumer.targets[1] != 8 ||
        consumer.targets[2] != UINT64_MAX - 7 || evidence.tls != 3 ||
        evidence.relative != 0) {
        return 0;
    }
    consumer.relocations[2].addend = 8;
    zero_bytes((uint8_t *)&evidence, sizeof(evidence));
    return !apply_object_relocations(&graph, 0, &layout, &evidence);
}

static int test_initializer_order(void) {
    ObjectGraph graph;
    InitializerEvidence evidence;
    uintptr_t initializers[4] = {
        (uintptr_t)&initializer_root,
        (uintptr_t)&initializer_provider,
        (uintptr_t)&initializer_observer,
        (uintptr_t)&initializer_core,
    };
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    initializer_count = 0;
    graph.object_count = 4;
    graph.relocation_count = 4;
    graph.relocation_order[0] = 3;
    graph.relocation_order[1] = 1;
    graph.relocation_order[2] = 2;
    graph.relocation_order[3] = 0;
    for (size_t index = 0; index < graph.object_count; ++index) {
        graph.objects[index].dynamic.init_array =
            (uintptr_t)&initializers[index];
        graph.objects[index].dynamic.init_array_size = sizeof(uintptr_t);
        graph.objects[index].loads[0].address = initializers[index];
        graph.objects[index].loads[0].memory_size = 1;
        graph.objects[index].loads[0].mapping_size = 1;
        graph.objects[index].loads[0].flags =
            PROGRAM_READABLE | PROGRAM_EXECUTABLE;
        graph.objects[index].load_count = 1;
    }
    if (!run_initializers(&graph, &evidence) || evidence.calls != 4 ||
        initializer_count != 4 || initializer_sequence[0] != 3 ||
        initializer_sequence[1] != 1 || initializer_sequence[2] != 2 ||
        initializer_sequence[3] != 0) {
        return 0;
    }
    initializer_count = 0;
    initializers[3] = (uintptr_t)&initializer_provider;
    return !run_initializers(&graph, &evidence);
}

static void add_executable_load(LoadedObject *object, size_t index,
                                uintptr_t address) {
    object->loads[index].address = address;
    object->loads[index].memory_size = 1;
    object->loads[index].mapping_size = 1;
    object->loads[index].flags = PROGRAM_READABLE | PROGRAM_EXECUTABLE;
    if (object->load_count <= index) {
        object->load_count = index + 1;
    }
}

static int test_finalizer_order(void) {
    ObjectGraph graph;
    FinalizationPlan plan;
    FinalizerEvidence evidence;
    uintptr_t root_array[2] = {
        (uintptr_t)&finalizer_root_first,
        (uintptr_t)&finalizer_root_second,
    };
    uintptr_t observer_array[1] = {
        (uintptr_t)&finalizer_observer_array,
    };
    uintptr_t provider_array[1] = {
        (uintptr_t)&finalizer_provider_array,
    };
    zero_bytes((uint8_t *)&graph, sizeof(graph));
    graph.object_count = 4;
    graph.relocation_count = 4;
    graph.relocation_order[0] = 3;
    graph.relocation_order[1] = 1;
    graph.relocation_order[2] = 2;
    graph.relocation_order[3] = 0;

    graph.objects[0].dynamic.fini_array = (uintptr_t)&root_array[0];
    graph.objects[0].dynamic.fini_array_size = sizeof(root_array);
    graph.objects[0].dynamic.fini_function =
        (uintptr_t)&finalizer_root_function;
    graph.objects[0].dynamic.has_fini_function = 1;
    add_executable_load(&graph.objects[0], 0,
                        (uintptr_t)&finalizer_root_first);
    add_executable_load(&graph.objects[0], 1,
                        (uintptr_t)&finalizer_root_second);
    add_executable_load(&graph.objects[0], 2,
                        (uintptr_t)&finalizer_root_function);

    graph.objects[1].dynamic.fini_array =
        (uintptr_t)&provider_array[0];
    graph.objects[1].dynamic.fini_array_size = sizeof(provider_array);
    graph.objects[1].dynamic.fini_function =
        (uintptr_t)&finalizer_provider_function;
    graph.objects[1].dynamic.has_fini_function = 1;
    add_executable_load(&graph.objects[1], 0,
                        (uintptr_t)&finalizer_provider_array);
    add_executable_load(&graph.objects[1], 1,
                        (uintptr_t)&finalizer_provider_function);

    graph.objects[2].dynamic.fini_array =
        (uintptr_t)&observer_array[0];
    graph.objects[2].dynamic.fini_array_size = sizeof(observer_array);
    graph.objects[2].dynamic.fini_function =
        (uintptr_t)&finalizer_observer_function;
    graph.objects[2].dynamic.has_fini_function = 1;
    add_executable_load(&graph.objects[2], 0,
                        (uintptr_t)&finalizer_observer_array);
    add_executable_load(&graph.objects[2], 1,
                        (uintptr_t)&finalizer_observer_function);

    graph.objects[3].dynamic.fini_function =
        (uintptr_t)&finalizer_core_function;
    graph.objects[3].dynamic.has_fini_function = 1;
    add_executable_load(&graph.objects[3], 0,
                        (uintptr_t)&finalizer_core_function);

    finalizer_count = 0;
    if (!prepare_finalization_plan(&graph, 1, &plan) ||
        plan.object_count != 4 || plan.expected_calls != 8 ||
        !run_finalizers(&plan, &evidence) || evidence.calls != 8 ||
        finalizer_count != 8 || finalizer_sequence[0] != 1 ||
        finalizer_sequence[1] != 0 || finalizer_sequence[2] != 2 ||
        finalizer_sequence[3] != 3 || finalizer_sequence[4] != 4 ||
        finalizer_sequence[5] != 5 || finalizer_sequence[6] != 6 ||
        finalizer_sequence[7] != 7 || run_finalizers(&plan, &evidence)) {
        return 0;
    }
    root_array[0] = (uintptr_t)&finalizer_core_function;
    return !prepare_finalization_plan(&graph, 1, &plan);
}

int main(void) {
    return test_names() && test_graph_order() && test_cycle_rejection() &&
                   test_symbol_scope() && test_symbol_versions() &&
                   test_tls_resolver_reference() &&
                   test_static_tls_layout() && test_dynamic_tls_index() &&
                   test_tls_relocation() &&
                   test_initializer_order() && test_finalizer_order()
               ? 0
               : 1;
}
