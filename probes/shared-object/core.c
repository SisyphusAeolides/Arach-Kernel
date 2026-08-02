#include <stdint.h>

static const uint64_t core_anchor = UINT64_C(0x1020304050607080);
static const uint64_t *volatile core_anchor_pointer
    __attribute__((used)) = &core_anchor;
static uint64_t core_stage;

__thread __attribute__((visibility("default"), tls_model("initial-exec")))
    uint64_t arach_core_tls = UINT64_C(0x0102030405060708);

uint64_t arach_core_value(uint64_t input);
uint64_t arach_core_finalize_step(uint64_t expected, uint64_t replacement);
void arach_core_finish(void);

static void __attribute__((constructor)) arach_core_initialize(void) {
    if (arach_core_tls == UINT64_C(0x0102030405060708)) {
        arach_core_tls = UINT64_C(0x1111111111111111);
        core_stage = UINT64_C(0x2222222222222222);
    }
}

__attribute__((visibility("default"))) uint64_t
arach_core_value(uint64_t input) {
    return input + *core_anchor_pointer + arach_core_tls + core_stage;
}

__attribute__((visibility("default"))) uint64_t
arach_core_finalize_step(uint64_t expected, uint64_t replacement) {
    if (arach_core_tls != expected) {
        return 0;
    }
    arach_core_tls = replacement;
    return 1;
}

static void __attribute__((destructor)) arach_core_finalize_array(void) {
    (void)arach_core_finalize_step(UINT64_C(0xbbbbbbbbbbbbbbbb),
                                   UINT64_C(0xcccccccccccccccc));
}

void arach_core_finish(void) {
    (void)arach_core_finalize_step(UINT64_C(0xcccccccccccccccc),
                                   UINT64_C(0xdddddddddddddddd));
}
