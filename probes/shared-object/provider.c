#include <stdint.h>

uint64_t arach_core_value(uint64_t input);
uint64_t arach_core_finalize_step(uint64_t expected, uint64_t replacement);
uint64_t arach_provider_value(uint64_t input);
uint64_t arach_provider_finalize_step(uint64_t expected,
                                      uint64_t replacement);
void arach_provider_finish(void);
static uint64_t provider_stage;

static void __attribute__((constructor)) arach_provider_initialize(void) {
    const uint64_t expected_core =
        UINT64_C(0x1020304050607080) + UINT64_C(0x1111111111111111) +
        UINT64_C(0x2222222222222222);
    if (arach_core_value(0) == expected_core) {
        provider_stage = UINT64_C(0x3333333333333333);
    }
}

__attribute__((visibility("default"))) uint64_t
arach_provider_value(uint64_t input) {
    return arach_core_value(input + UINT64_C(0x1111222233334444)) +
           provider_stage;
}

__attribute__((visibility("default"))) uint64_t
arach_provider_finalize_step(uint64_t expected, uint64_t replacement) {
    return arach_core_finalize_step(expected, replacement);
}

static void __attribute__((destructor)) arach_provider_finalize_array(void) {
    (void)arach_core_finalize_step(UINT64_C(0x9999999999999999),
                                   UINT64_C(0xaaaaaaaaaaaaaaaa));
}

void arach_provider_finish(void) {
    (void)arach_core_finalize_step(UINT64_C(0xaaaaaaaaaaaaaaaa),
                                   UINT64_C(0xbbbbbbbbbbbbbbbb));
}
