#include <stdint.h>

uint64_t arach_provider_value(uint64_t input);
uint64_t arach_observer_value(uint64_t input);

uint64_t arach_shared_probe(uint64_t input);
static uint64_t root_stage;

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
    return arach_provider_value(input) ^ arach_observer_value(input) ^
           UINT64_C(0xa5a55a5af0f00f0f) ^ root_stage;
}
