#include <stdint.h>

uint64_t arach_provider_value(uint64_t input);
uint64_t arach_observer_value(uint64_t input);

uint64_t arach_shared_probe(uint64_t input);

__attribute__((visibility("default"))) uint64_t
arach_shared_probe(uint64_t input) {
    return arach_provider_value(input) ^ arach_observer_value(input) ^
           UINT64_C(0xa5a55a5af0f00f0f);
}
