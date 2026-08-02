#include <stddef.h>
#include <stdint.h>

uint64_t arach_provider_value(uint64_t input);
uint64_t arach_provider_finalize_step(uint64_t expected,
                                      uint64_t replacement);
uint64_t arach_observer_value(uint64_t input);
uint64_t arach_scope_choice(uint64_t input) __attribute__((weak));
uint64_t arach_optional_hook(uint64_t input) __attribute__((weak));
extern const uint64_t arach_data_choice __attribute__((weak));
extern const uint64_t arach_provider_data;
extern const uint64_t arach_provider_vector[3];
extern const uint64_t arach_optional_data __attribute__((weak));

uint64_t arach_shared_probe(uint64_t input);
void arach_root_finish(void);
static uint64_t root_stage;
static uint64_t (*volatile absolute_provider_function)(uint64_t)
    __attribute__((used)) = arach_provider_value;
static const uint64_t *volatile absolute_provider_vector
    __attribute__((used)) = &arach_provider_vector[1];
static const uint64_t *volatile absolute_weak_data
    __attribute__((used)) = &arach_data_choice;
static const uint64_t *volatile absolute_optional_data
    __attribute__((used)) = &arach_optional_data;

static __attribute__((used, noinline)) uint64_t
arach_optional_weak_probe(uint64_t input) {
    return arach_optional_hook(input);
}

static __attribute__((used, noinline)) uint64_t
arach_optional_data_probe(void) {
    return &arach_optional_data == NULL
               ? UINT64_C(0x2468ace013579bdf)
               : arach_optional_data;
}

static __attribute__((used, noinline)) uint64_t
arach_absolute_optional_data_probe(void) {
    return absolute_optional_data == NULL
               ? UINT64_C(0x3141592653589793)
               : *absolute_optional_data;
}

static void __attribute__((constructor)) arach_root_initialize(void) {
    const uint64_t core = UINT64_C(0x1020304050607080) +
                          UINT64_C(0x1111111111111111) +
                          UINT64_C(0x2222222222222222);
    const uint64_t provider = UINT64_C(0x1111222233334444) + core +
                              UINT64_C(0x3333333333333333);
    const uint64_t observer = UINT64_C(0x0f0ff0f05a5aa5a5) + core +
                              UINT64_C(0x4444444444444444);
    if (arach_provider_value(0) == provider &&
        arach_observer_value(0) == observer) {
        root_stage = UINT64_C(0x5555555555555555);
    }
}

__attribute__((visibility("default"))) uint64_t
arach_shared_probe(uint64_t input) {
    return absolute_provider_function(input) ^ arach_observer_value(input) ^
           arach_scope_choice(input) ^
           (arach_data_choice + *absolute_weak_data) ^ arach_provider_data ^
           *absolute_provider_vector ^ arach_optional_data_probe() ^
           arach_absolute_optional_data_probe() ^
           UINT64_C(0xa5a55a5af0f00f0f) ^ root_stage;
}

static void __attribute__((destructor)) arach_root_finalize_array(void) {
    (void)arach_provider_finalize_step(UINT64_C(0x1111111111111111),
                                       UINT64_C(0x6666666666666666));
}

void arach_root_finish(void) {
    (void)arach_provider_finalize_step(UINT64_C(0x6666666666666666),
                                       UINT64_C(0x7777777777777777));
}
