#include <stdint.h>

uint64_t arach_core_value(uint64_t input);
uint64_t arach_provider_value(uint64_t input);

__attribute__((visibility("default"))) uint64_t
arach_provider_value(uint64_t input) {
    return arach_core_value(input + UINT64_C(0x1111222233334444));
}
