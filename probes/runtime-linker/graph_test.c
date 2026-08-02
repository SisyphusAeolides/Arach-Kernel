#include "runtime_linker.c"

typedef struct {
    uint32_t hash[5];
    Elf64Symbol symbols[2];
    char strings[32];
} SymbolFixture;

static uintptr_t first_definition(uintptr_t value);
static uintptr_t second_definition(uintptr_t value);
static int set_name(ObjectName *name, const char *value, size_t length);
static void prepare_symbol_object(LoadedObject *object, SymbolFixture *fixture,
                                  uintptr_t definition);
static int test_names(void);
static int test_graph_order(void);
static int test_cycle_rejection(void);
static int test_symbol_scope(void);
int main(void);

static uintptr_t first_definition(uintptr_t value) { return value + 1; }

static uintptr_t second_definition(uintptr_t value) { return value + 2; }

static int set_name(ObjectName *name, const char *value, size_t length) {
    return copy_object_name(value, length + 1, name);
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
    return resolve_global_symbol(&graph, 2, "shared_definition",
                                 sizeof("shared_definition") - 1, &address) &&
           address == (uintptr_t)&first_definition;
}

int main(void) {
    return test_names() && test_graph_order() && test_cycle_rejection() &&
                   test_symbol_scope()
               ? 0
               : 1;
}
