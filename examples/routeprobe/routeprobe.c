/* MIT-licensed synthetic two-level dispatcher; lineage is recorded in ORIGIN.md. */
#include <stddef.h>
#include <stdint.h>

enum { ROUTE_BEGIN, ROUTE_CHECK, ROUTE_MIX, ROUTE_RETURN, ROUTE_COUNT };
static const int ROUTE_PERMUTATION[ROUTE_COUNT] = { 3, 1, 0, 2 };

int routeprobe(const uint8_t *source_bytes, size_t byte_count, uint8_t *result_bytes)
{
    int route_indices[ROUTE_COUNT];
    void *route_destinations[ROUTE_COUNT];
    for (int route_number = 0; route_number < ROUTE_COUNT; ++route_number)
        route_indices[route_number] = ROUTE_PERMUTATION[route_number];
    route_destinations[ROUTE_PERMUTATION[ROUTE_BEGIN]] = &&begin_mix;
    route_destinations[ROUTE_PERMUTATION[ROUTE_CHECK]] = &&check_remaining;
    route_destinations[ROUTE_PERMUTATION[ROUTE_MIX]] = &&mix_byte;
    route_destinations[ROUTE_PERMUTATION[ROUTE_RETURN]] = &&return_digest;
    volatile int active_route = ROUTE_BEGIN;
    size_t byte_position = 0;
    uint32_t rolling_digest = 0x1234u;
route_hub:
    {
        int handler_number = route_indices[active_route];
        goto *route_destinations[handler_number];
    }
begin_mix:
    byte_position = 0;
    rolling_digest = 0x1234u;
    active_route = ROUTE_CHECK;
    goto route_hub;
check_remaining:
    active_route = byte_position < byte_count ? ROUTE_MIX : ROUTE_RETURN;
    goto route_hub;
mix_byte:
    {
        uint8_t mixed_byte = (uint8_t)((source_bytes[byte_position] ^ 0x5Au) +
                                      (uint8_t)(byte_position * 7u));
        result_bytes[byte_position++] = mixed_byte;
        rolling_digest = rolling_digest * 0x01000193u + mixed_byte;
        active_route = ROUTE_CHECK;
        goto route_hub;
    }
return_digest:
    return (int)(rolling_digest & 0xFFu);
}
