#include <stdint.h>

uint64_t arach_core_value(uint64_t input);
uint64_t arach_provider_value(uint64_t input);
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
