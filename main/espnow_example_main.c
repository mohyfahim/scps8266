/* ESPNOW Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
   This example shows how to use ESPNOW.
   Prepare two device, one for sending ESPNOW data and another for receiving
   ESPNOW data.
*/
#include "comm_core.h"
#include "comp_core.h"
#include "driver/uart.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "espnow.h"
#include "espnow_example.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"
#include "nvs_flash.h"
#include "rom/crc.h"
#include "rom/ets_sys.h"
#include "tcpip_adapter.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static const char *TAG = "espnow_example";

#define EX_UART_NUM UART_NUM_0
#define BUF_SIZE 128
#define TD_BUF_SIZE (sizeof(Data_Transmitter) + 1 + 2)
#define RD_BUF_SIZE (TD_BUF_SIZE)
static QueueHandle_t uart0_queue;

static xQueueHandle example_espnow_queue;

static uint8_t example_broadcast_mac[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF,
                                                          0xFF, 0xFF, 0xFF};
static void uart_event_task(void *pvParameters) {
  uart_event_t event;
  uint8_t *dtmp = (uint8_t *)malloc(RD_BUF_SIZE);
  int err;
  for (;;) {
    // Waiting for UART event.
    if (xQueueReceive(uart0_queue, (void *)&event,
                      (portTickType)portMAX_DELAY)) {
      bzero(dtmp, RD_BUF_SIZE);
      ESP_LOGI(TAG, "uart[%d] event:", EX_UART_NUM);

      switch (event.type) {
      // Event of UART receving data
      // We'd better handler data event fast, there would be much more data
      // events than other types of events. If we take too much time on data
      // event, the queue might be full.
      case UART_DATA: {
        ESP_LOGI(TAG, "[UART DATA]: %d", event.size);
        uart_read_bytes(EX_UART_NUM, dtmp, event.size, portMAX_DELAY);
        ESP_LOGI(TAG, "[DATA EVT]:");
        if (dtmp[0] == '#' && dtmp[event.size - 1] == '#') {
          err = nw_send_packet(dtmp + 1, event.size - 2, ESPNOW_ADDR_BROADCAST,
                               ESPNOW_TYPE_SCPS_DATA, NW_DATA_TYPE);

          if (err != ESP_OK) {
            ESP_LOGE(TAG, "can't send data: %s", esp_err_to_name(err));
          } else {
            ESP_LOGI(TAG, " data sent successfuly");
          }
        } else {
          ESP_LOGE(TAG, "error in header and footer %.*s", event.size,
                   (char *)dtmp);
        }

      } break;

      // Event of HW FIFO overflow detected
      case UART_FIFO_OVF:
        ESP_LOGI(TAG, "hw fifo overflow");
        // If fifo overflow happened, you should consider adding flow control
        // for your application. The ISR has already reset the rx FIFO, As an
        // example, we directly flush the rx buffer here in order to read more
        // data.
        uart_flush_input(EX_UART_NUM);
        xQueueReset(uart0_queue);
        break;

      // Event of UART ring buffer full
      case UART_BUFFER_FULL:
        ESP_LOGI(TAG, "ring buffer full");
        // If buffer full happened, you should consider encreasing your buffer
        // size As an example, we directly flush the rx buffer here in order to
        // read more data.
        uart_flush_input(EX_UART_NUM);
        xQueueReset(uart0_queue);
        break;

      case UART_PARITY_ERR:
        ESP_LOGI(TAG, "uart parity error");
        break;

      // Event of UART frame error
      case UART_FRAME_ERR:
        ESP_LOGI(TAG, "uart frame error");
        break;

      // Others
      default:
        ESP_LOGI(TAG, "uart event type: %d", event.type);
        break;
      }
    }
  }

  free(dtmp);
  dtmp = NULL;
  vTaskDelete(NULL);
}
/* WiFi should start before using ESPNOW */
static void example_wifi_init(void) {
  tcpip_adapter_init();

  ESP_ERROR_CHECK(esp_event_loop_create_default());

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());

  /* In order to simplify example, channel is set after WiFi started.
   * This is not necessary in real application if the two devices have
   * been already on the same channel.
   */
  ESP_ERROR_CHECK(esp_wifi_set_channel(13, (wifi_second_chan_t)0));
}

void data_receiving(void *params) {
  nw_packet_t *r_data = (nw_packet_t *)heap_caps_malloc(
      sizeof(nw_packet_t) + ESPNOW_DATA_LEN, MALLOC_CAP_8BIT);
  uint8_t *dtmp = (uint8_t *)malloc(TD_BUF_SIZE);
  dtmp[0] = '#';
  dtmp[TD_BUF_SIZE - 1] = '#';

  size_t r_len = 0;
  esp_err_t err = ESP_OK;
  int8_t rssi = 0;
  uint8_t rcv_mac[6];
  ESP_LOGW(TAG, "data rec start");
  while (true) {
    err = nw_receive_packet(r_data, &r_len, ESPNOW_TYPE_SCPS_CONFIG, rcv_mac,
                            &rssi);
    ESP_ERROR_CONTINUE(err != ESP_OK, "");
    ESP_LOGI(TAG, "received %d + %p", r_len, r_data);
    ESP_LOGI(TAG, "size %d", r_data->header.size);
    Data_Receiver *r_buffer = (Data_Receiver *)r_data->body;
    if (r_data->header.type == NW_SYS_CONFIG_TYPE) {
      dtmp[1] = 0;
      memcpy(dtmp + 2, (uint8_t *)r_buffer, sizeof(Data_Receiver));
      ESP_LOGI(TAG, "sys: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
               r_buffer->HVAC1_Command, r_buffer->HVAC2_Command,
               r_buffer->HVAC3_Command, r_buffer->FanAir1_Command,
               r_buffer->FanAir2_Command, r_buffer->HVACMode,
               r_buffer->WorkMode, r_buffer->Permission,
               r_buffer->User_Setpoint, r_buffer->HVAC1_Setpoint,
               r_buffer->HVAC2_Setpoint, r_buffer->HVAC3_Setpoint);
      err = uart_write_bytes(EX_UART_NUM, (const char *)dtmp, TD_BUF_SIZE);
      if (err < 1) {
        ESP_LOGE(TAG, "cannot write to serial");
      }
    } else if (r_data->header.type == NW_ROUTINE_CONFIG_TYPE) {
      dtmp[1] = 1;
      memcpy(dtmp + 2, (uint8_t *)r_buffer, sizeof(Data_Receiver));

      ESP_LOGI(TAG, "routine: %.2f,%.2f,%.2f",
               r_buffer->OtherRoom_Temperature.float_,
               r_buffer->Outside_Temperature.float_,
               r_buffer->EngineRoom_Temperature.float_);
      uart_write_bytes(EX_UART_NUM, (const char *)r_buffer,
                       r_data->header.size);
    } else {
      ESP_LOGE(TAG, "invalid subtype");
    }
  }
  vTaskDelete(NULL);
}

void app_main() {
  // Initialize NVS
  esp_err_t err;
  ESP_ERROR_CHECK(nvs_flash_init());

  example_wifi_init();

  espnow_config_t espnow_config = ESPNOW_INIT_CONFIG_DEFAULT();
  espnow_config.qsize.data = 16;
  espnow_config.qsize.scps_nw = 16;
  // espnow_config.qsize.scps_sec = 16;
  espnow_config.qsize.scps_data = 8;
  espnow_config.qsize.scps_config = 8;

  err = espnow_init(&espnow_config);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "espnow init failed %s", esp_err_to_name(err));
    return;
  }

  uart_config_t uart_config = {.baud_rate = 115200,
                               .data_bits = UART_DATA_8_BITS,
                               .parity = UART_PARITY_DISABLE,
                               .stop_bits = UART_STOP_BITS_1,
                               .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};
  uart_param_config(EX_UART_NUM, &uart_config);

  // Install UART driver, and get the queue.
  uart_driver_install(EX_UART_NUM, BUF_SIZE * 2, 0, 100, &uart0_queue, 0);

  xTaskCreate(uart_event_task, "data_send_start", 20 * 1024, NULL, 1, NULL);
  xTaskCreate(data_receiving, "data_read_start", 20 * 1024, NULL, 1, NULL);
}
