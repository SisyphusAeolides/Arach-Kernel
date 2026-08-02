#include <stdint.h>

uint64_t arach_core_value(uint64_t input);
uint64_t arach_core_finalize_step(uint64_t expected, uint64_t replacement);
extern __thread __attribute__((tls_model("global-dynamic")))
    uint64_t arach_core_tls;
uint64_t arach_provider_value(uint64_t input);
uint64_t arach_provider_finalize_step(uint64_t expected,
                                      uint64_t replacement);
uint64_t arach_scope_choice(uint64_t input);
void arach_provider_finish(void);
static uint64_t provider_stage;

__attribute__((weak, visibility("default"))) const uint64_t
    arach_data_choice = UINT64_C(0x0c0ffee0ddf00d42);

__attribute__((visibility("default"))) const uint64_t arach_provider_data =
    UINT64_C(0x5a5aa5a596966969);

__attribute__((visibility("default"))) const uint64_t
    arach_provider_vector[3] = {
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0x89abcdef01234567),
        UINT64_C(0xfedcba9876543210),
    };

static void __attribute__((constructor)) arach_provider_initialize(void) {
    const uint64_t expected_core =
        UINT64_C(0x1020304050607080) + UINT64_C(0x1111111111111111) +
        UINT64_C(0x2222222222222222);
    if (arach_core_value(0) == expected_core &&
        arach_core_tls == UINT64_C(0x1111111111111111)) {
        provider_stage = UINT64_C(0x3333333333333333);
    }
}

__attribute__((visibility("default"))) uint64_t
arach_provider_value(uint64_t input) {
    if (arach_core_tls != UINT64_C(0x1111111111111111)) {
        return 0;
    }
    return arach_core_value(input + UINT64_C(0x1111222233334444)) +
           provider_stage;
}

__attribute__((visibility("default"))) uint64_t
arach_provider_finalize_step(uint64_t expected, uint64_t replacement) {
    return arach_core_finalize_step(expected, replacement);
}

__attribute__((weak, visibility("default"))) uint64_t
arach_scope_choice(uint64_t input) {
    return input + UINT64_C(0x13579bdf2468ace0);
}

static void __attribute__((destructor)) arach_provider_finalize_array(void) {
    (void)arach_core_finalize_step(UINT64_C(0x9999999999999999),
                                   UINT64_C(0xaaaaaaaaaaaaaaaa));
}

void arach_provider_finish(void) {
    (void)arach_core_finalize_step(UINT64_C(0xaaaaaaaaaaaaaaaa),
                                   UINT64_C(0xbbbbbbbbbbbbbbbb));
}
