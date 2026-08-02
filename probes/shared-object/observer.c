#include <stdint.h>

uint64_t arach_core_value(uint64_t input);
uint64_t arach_core_finalize_step(uint64_t expected, uint64_t replacement);
uint64_t arach_observer_value(uint64_t input);
uint64_t arach_scope_choice(uint64_t input);
void arach_observer_finish(void);
static uint64_t observer_stage;

__attribute__((visibility("default"))) const uint64_t arach_data_choice =
    UINT64_C(0xdeadbeefcafef00d);

static void __attribute__((constructor)) arach_observer_initialize(void) {
    const uint64_t expected_core =
        UINT64_C(0x1020304050607080) + UINT64_C(0x1111111111111111) +
        UINT64_C(0x2222222222222222);
    if (arach_core_value(0) == expected_core) {
        observer_stage = UINT64_C(0x4444444444444444);
    }
}

__attribute__((visibility("default"))) uint64_t
arach_observer_value(uint64_t input) {
    return arach_core_value(input ^ UINT64_C(0x0f0ff0f05a5aa5a5)) +
           observer_stage;
}

__attribute__((visibility("default"))) uint64_t
arach_scope_choice(uint64_t input) {
    return input ^ UINT64_C(0xfedcba9876543210);
}

static void __attribute__((destructor)) arach_observer_finalize_array(void) {
    (void)arach_core_finalize_step(UINT64_C(0x7777777777777777),
                                   UINT64_C(0x8888888888888888));
}

void arach_observer_finish(void) {
    (void)arach_core_finalize_step(UINT64_C(0x8888888888888888),
                                   UINT64_C(0x9999999999999999));
}
