#include <stdint.h>

static const uint64_t provider_anchor = UINT64_C(0x1020304050607080);
static const uint64_t *volatile provider_anchor_pointer
    __attribute__((used)) = &provider_anchor;

uint64_t arach_provider_value(uint64_t input);

__attribute__((visibility("default"))) uint64_t
arach_provider_value(uint64_t input) {
    return input + *provider_anchor_pointer;
}
