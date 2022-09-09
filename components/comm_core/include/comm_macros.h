#pragma once

#include "esp_timer.h"

#ifdef __cplusplus
extern "C"
{
#endif /**< _cplusplus */

#define CHECK_TIMEOUT(base_time, now, criteria) (now - base_time > criteria)

#define MILLIS() (int32_t)(esp_timer_get_time() / 1000)

#define NW_DISCOVERY_TIMEOUT 300
#define NW_DISCOVERY_BC_TIMEOUT 100
#define NW_MDF_GRAPH_TIMEOUT 60000
#define NW_MDF_ROOT_READ_TIMEOUT 1000
#define NW_SECURITY_START_TIMEOUT 250
#define NW_SECURITY_START_BC_TIMEOUT 10

#define NW_SECURITY_FINISH_PACKET_NUMS 5
#define NW_SECURITY_FINISH_WAITH 1000
#define NW_SECURITY_LOCAL_QUANTIZE_VALUE 10
#define NW_SECURITY_BCH_M 7
#define NW_SECURITY_BCH_T 23

#ifdef __cplusplus
}
#endif /**< _cplusplus */
