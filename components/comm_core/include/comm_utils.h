#pragma once

#include "esp_heap_caps.h"
#include "esp_random.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /**< _cplusplus */

uint16_t crc16(uint16_t crc, const uint8_t *buf, size_t size);

void random_vector_generator(uint8_t *buffer, size_t len);

uint8_t *local_mean_quantizer(int8_t *vector, uint16_t &len, int distance);

#ifdef __cplusplus
}
#endif /**< _cplusplus */
