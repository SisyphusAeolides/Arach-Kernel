#include <stdint.h>

static const uint64_t core_anchor = UINT64_C(0x1020304050607080);
static const uint64_t *volatile core_anchor_pointer
    __attribute__((used)) = &core_anchor;

uint64_t arach_core_value(uint64_t input);

__attribute__((visibility("default"))) uint64_t
arach_core_value(uint64_t input) {
    return input + *core_anchor_pointer;
}
