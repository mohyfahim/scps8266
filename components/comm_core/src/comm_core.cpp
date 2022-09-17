#include "array"
#include "cstring"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include "esp_timer.h"
#include "esp_wifi.h"

#include "map"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "comm_core.h"
#include "comm_macros.h"
#include "comm_sec.h"
#include "comm_types.h"
#include "espnow.h"

static const char *TAG = "comm_core";
static int test_payload = 0;
static bool is_ch = false;
static bool get_ip = false;
typedef std::array<uint8_t, 6> nw_mac_t;
std::map<nw_mac_t, int8_t> nw_table;
nw_discovery_start_packet_t nw_discovery = {};
uint8_t my_mac[ESPNOW_ADDR_LEN] = {0};
bool is_inited = true;
bool start_to_aggr = false;
bool send_discovery = false;
bool send_beacon_graph = false;
int send_beacon_counter = 0;
bool send_nw_table_to_root = false;
bool get_is_inited() { return is_inited; }
static nw_data_init_packet_t init_packet_body = {};
nw_packet_t *packet =
    (nw_packet_t *)heap_caps_malloc(ESPNOW_DATA_LEN, MALLOC_CAP_8BIT);

nw_packet_t *rcv_packet =
    (nw_packet_t *)heap_caps_malloc(ESPNOW_DATA_LEN, MALLOC_CAP_8BIT);

#define CONFIG_MESH_CHANNEL 13

esp_err_t nw_send_packet(uint8_t *data, size_t len, const uint8_t *dest_addr,
                         espnow_type_t type, nw_packet_type_t subtype, bool ack,
                         time_t timeout_millis) {
  espnow_frame_head_t frame_head = {
      .channel = 0,
      .broadcast = true,
      .ack = ack,
      .retransmit_count = 10,
  };
  // TODO: support fragmentation.
  int packet_len = sizeof(nw_packet_t) + len;
  packet->header.seq = 0;
  packet->header.size = len;
  packet->header.type = subtype;

  if (len)
    memcpy(packet->body, data, len);

  esp_err_t err = espnow_send(type, dest_addr, packet, packet_len, &frame_head,
                              pdMS_TO_TICKS(timeout_millis));

  return err;
}

esp_err_t nw_receive_packet(nw_packet_t *data, size_t *len, espnow_type_t type,
                            uint8_t addr[6], int8_t *rssi) {

  wifi_pkt_rx_ctrl_t rx_ctrl = {0};

  // TODO: support fragmentation.
  esp_err_t err = espnow_recv(type, addr, (uint8_t *)data, len, &rx_ctrl,
                              pdMS_TO_TICKS(1000));
  if (err == ESP_OK) {
    ESP_LOGW(TAG, "in func %d + %p", data->header.size, data);
    if (memcmp(addr, my_mac, ESPNOW_ADDR_LEN)) {
      ESP_LOGW(TAG, "received for broadcast ? " MACSTR, MAC2STR(addr));
      // memset(data, 0, sizeof(nw_packet_t) + ESPNOW_DATA_LEN);
      // return ESP_FAIL;
    }
    *rssi = rx_ctrl.rssi;
  }

  return err;
}
