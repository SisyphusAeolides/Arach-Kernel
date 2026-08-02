#include <stdint.h>

static const uint64_t shared_anchor = UINT64_C(0x1020304050607080);
static const uint64_t *volatile shared_anchor_pointer
    __attribute__((used)) = &shared_anchor;

uint64_t arach_shared_probe(uint64_t input);

__attribute__((visibility("default"))) uint64_t
arach_shared_probe(uint64_t input) {
    return input + *shared_anchor_pointer;
}
