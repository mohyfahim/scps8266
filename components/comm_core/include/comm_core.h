#pragma once
#include "comm_types.h"
#include "esp_err.h"
#include "espnow.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/portmacro.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#define MQTT_BROKER_ADDR "mqtt.giot.ir"
// #define MQTT_BROKER_ADDR "192.168.1.6"

#ifdef __cplusplus
extern "C" {
#endif /**< _cplusplus */

/**
 * @brief set init parameters to send for the first time to server
 *
 * @param NumberOfHVAC
 * @param NumberOfFanAir
 * @param HVACType
 */

void nw_set_init_data(uint16_t NumberOfHVAC, uint16_t NumberOfFanAir,
                      uint8_t HVACType);
/**
 * @brief
 *
 */
void commu_task_start(void *params);

/**
 * @brief receive packets
 *
 * @param data  data buffer pointer that is allocated by the function.
 * @param len  size of received data
 * @return esp_err_t returns ESP_OK if receive something or returns ESP_FAIL if
 * timeout happens.
 */
esp_err_t nw_receive_packet(nw_packet_t *data, size_t *len, espnow_type_t type,
                            uint8_t addr[6], int8_t *rssi);
/**
 * @brief send data packet
 *
 * @param data the pointer of your struct
 * @param len  the size of your data in struct. note: you should define your
 * struct with __attribute__((packed)).
 * @return esp_err_t returns ESP_OK if receives something or returns ESP_FAIL if
 * timeout happens.
 */

esp_err_t nw_send_packet(uint8_t *data, size_t len, const uint8_t *dest_addr,
                         espnow_type_t type, nw_packet_type_t subtype, bool ack,
                         time_t timeout_millis);

bool get_is_inited();

#ifdef __cplusplus
}
#endif /**< _cplusplus */
