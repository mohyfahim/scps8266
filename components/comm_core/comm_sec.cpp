
#include "cstring"
#include "fstream"
#include "iostream"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_spiffs.h"
#include "esp_wifi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "comm_macros.h"
#include "comm_sec.h"
#include "comm_types.h"
#include "comm_utils.h"
#include "esp_bch.h"
#include "espnow.h"

static const char *TAG = "comm_sec";

comm_sec_t nw_comm_sec;
FILE *sec_log;
static bool first_time = true;

static void nw_security_task(void *params) {

  uint8_t my_mac[ESPNOW_ADDR_LEN] = {0};
  ESP_ERROR_CHECK(esp_read_mac(my_mac, ESP_MAC_WIFI_STA));
  esp_err_t err = ESP_OK;
  size_t size = ESPNOW_DATA_LEN;
  nw_packet_t *data =
      (nw_packet_t *)heap_caps_malloc(ESPNOW_DATA_LEN, MALLOC_CAP_8BIT);
  uint8_t addr[ESPNOW_ADDR_LEN] = {0};
  wifi_pkt_rx_ctrl_t rx_ctrl = {0};
  espnow_frame_head_t frame_head = {
      .broadcast = true,
      .retransmit_count = 10,
  };
  bool is_first = true;
  bool wait_for_response = false;
  int start_len = sizeof(nw_packet_t) + sizeof(nw_security_start_packet_t);
  int resp_len = sizeof(nw_packet_t) + sizeof(nw_security_response_packet_t);
  int init_len = sizeof(nw_packet_t) + sizeof(nw_security_initiator_packet_t);
  int finish_len = sizeof(nw_packet_t) + sizeof(nw_security_finish_packet_t);
  int key_start_len =
      sizeof(nw_packet_t) + sizeof(nw_security_key_start_packet_t);
  int key_response_len =
      sizeof(nw_packet_t) + sizeof(nw_security_key_response_packet_t);

  int key_ack_len = sizeof(nw_packet_t) + sizeof(nw_security_key_ack_packet_t);
  nw_packet_t *start_packet =
      (nw_packet_t *)heap_caps_malloc(start_len, MALLOC_CAP_DEFAULT);
  start_packet->header.seq = 0;
  start_packet->header.size = sizeof(nw_security_start_packet_t);
  start_packet->header.type = NW_SECURITY_START_TYPE;
  nw_packet_t *finish_packet =
      (nw_packet_t *)heap_caps_malloc(finish_len, MALLOC_CAP_DEFAULT);
  finish_packet->header.size = sizeof(nw_security_finish_packet_t);
  finish_packet->header.type = NW_SECURITY_FINISH_TYPE;
  nw_packet_t *resp_packet =
      (nw_packet_t *)heap_caps_malloc(resp_len, MALLOC_CAP_DEFAULT);
  nw_packet_t *init_packet =
      (nw_packet_t *)heap_caps_malloc(init_len, MALLOC_CAP_DEFAULT);
  init_packet->header.seq = 0;
  init_packet->header.size = sizeof(nw_security_initiator_packet_t);
  init_packet->header.type = NW_SECURITY_INIT_TYPE;
  nw_security_initiator_packet_t init_packet_body = {};
  init_packet_body.failed_index = -1;

  nw_security_response_packet_t resp_packet_body = {};

  nw_packet_t *key_start_packet =
      (nw_packet_t *)heap_caps_malloc(key_start_len, MALLOC_CAP_DEFAULT);
  key_start_packet->header.type = NW_SECURITY_KEY_START_TYPE;
  key_start_packet->header.size = sizeof(nw_security_key_start_packet_t);
  nw_security_key_start_packet_t key_start_packet_body = {};

  nw_packet_t *key_reponse_packet =
      (nw_packet_t *)heap_caps_malloc(key_response_len, MALLOC_CAP_8BIT);
  key_reponse_packet->header.type = NW_SECURITY_KEY_RESPONSE_TYPE;
  key_reponse_packet->header.size = sizeof(nw_security_key_response_packet_t);
  nw_security_key_response_packet_t key_response_packet_body = {};
  key_response_packet_body.failed_index = -1;
  key_response_packet_body.final_index = -1;

  nw_packet_t *key_ack_packet =
      (nw_packet_t *)heap_caps_malloc(key_ack_len, MALLOC_CAP_8BIT);
  key_ack_packet->header.type = NW_SECURITY_KEY_ACK_TYPE;
  key_ack_packet->header.size = sizeof(nw_security_key_ack_packet_t);
  nw_security_key_ack_packet_t key_ack_packet_body = {};

  int32_t now = 0;
  bool flag_rec = false;
  int8_t num_childs = 1;
  int8_t num_childs_counter = 0;
  int16_t rounds = 0;
  uint16_t vector_len = 20;
  int16_t internal_rounds = -1;
  int8_t pref = 0;
  uint8_t *quantized;
  struct bch_control *bch;
  uint16_t cypher_len = 0;
  uint16_t random_mask_len = 0;
  uint8_t *random_mask;
  uint16_t crc_buffer;
  uint32_t *err_loc;
  bool pass_round = true;

  // FIXME: only define this if it is not ch!
  int8_t *prefs = (int8_t *)heap_caps_malloc(vector_len * 1, MALLOC_CAP_8BIT);
  short int *prefs_indexes = (short int *)heap_caps_malloc(
      vector_len * sizeof(short int), MALLOC_CAP_8BIT);
  ESP_LOGI(TAG, "nw_security start");
  uint8_t *final_vector =
      (uint8_t *)heap_caps_malloc(vector_len / 8, MALLOC_CAP_8BIT);
  int final_index = 0;
  int internal_final_index = 0;

  while (rounds < vector_len) { // NOTE: we have challenges at the final round
    int32_t base_time = MILLIS();

    if (nw_comm_sec.is_ch) {
      num_childs_counter = 0;
      // if (first_time) {
      //   sec_log = fopen("/spiffs/seclog.txt", "w");
      //   if (sec_log == NULL) {
      //     ESP_LOGE(TAG, "Failed to open file for writing");
      //     break;
      //   }
      //   first_time = false;
      // }

      start_packet->header.seq = rounds;
      err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                        start_packet, start_len, &frame_head,
                        pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
      ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                         esp_err_to_name(err));
      // base_time = MILLIS();
      do {
        now = MILLIS();
        err =
            espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                        &rx_ctrl, pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
        ESP_ERROR_CONTINUE(err != ESP_OK, "");

        if (data->header.type == NW_SECURITY_INIT_TYPE) {
          num_childs_counter++;
          ESP_LOGW(TAG, " received init, is first ? %d and seq %d and round %d",
                   is_first, data->header.seq, rounds);
          resp_packet->header.seq = data->header.seq;
          resp_packet->header.size = sizeof(nw_security_response_packet_t);
          resp_packet->header.type = NW_SECURITY_RESP_TYPE;
          memcpy(resp_packet_body.addr, addr, 6);

          if (is_first) {
            pref = rx_ctrl.rssi;
            resp_packet_body.is_first = true;
            resp_packet_body.value = 0;
            memcpy(resp_packet->body, &resp_packet_body,
                   sizeof(nw_security_response_packet_t));
            is_first = false;
            prefs_indexes[rounds] = data->header.seq;
            prefs[rounds] = pref;
          } else {
            resp_packet_body.is_first = false;
            resp_packet_body.value = rx_ctrl.rssi - pref;
            memcpy(resp_packet->body, &resp_packet_body,
                   sizeof(nw_security_response_packet_t));
          }
          err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                            resp_packet, resp_len, &frame_head,
                            pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
          ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                             esp_err_to_name(err));
          memcpy(&init_packet_body, data->body,
                 sizeof(nw_security_initiator_packet_t));
          if (init_packet_body.failed_index != -1 &&
              init_packet_body.failed_index < rounds) {
            if ((internal_rounds == -1) ||
                (internal_rounds != -1 &&
                 init_packet_body.failed_index < internal_rounds)) {
              internal_rounds = init_packet_body.failed_index;
            }
          }
          ESP_LOGW(TAG, "pref is %d ", pref);
          // fprintf(sec_log, "%d," MACSTR ",%d,%d,%d,%d\n", rounds,
          // MAC2STR(addr),
          //         rx_ctrl.rssi, resp_packet_body.is_first, pref,
          //         resp_packet->header.seq);

          base_time = now;
        }

      } while (!CHECK_TIMEOUT(base_time, now, NW_SECURITY_START_TIMEOUT));

      if (num_childs != num_childs_counter) {
        ESP_LOGE(TAG, "some node is missing in seq:%d",
                 start_packet->header.seq);
        vTaskDelay(4 * NW_SECURITY_START_TIMEOUT);
      } else {
        // start_packet->header.seq++;
        rounds++;
      }
      if (internal_rounds != -1) {
        ESP_LOGE(TAG, "some node reports missing in seq:%d", internal_rounds);
        rounds = internal_rounds;
        internal_rounds = -1;
        // vTaskDelay(4 * NW_SECURITY_START_TIMEOUT);
      }

    } else {
      err = espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                        &rx_ctrl, pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
      ESP_ERROR_CONTINUE(err != ESP_OK, "");

      if (data->header.type == NW_SECURITY_START_TYPE) {
        // ESP_LOGW(TAG, "receive start packet");
        // if (first_time) {
        //   sec_log = fopen("/spiffs/seclog.txt", "w");
        //   if (sec_log == NULL) {
        //     ESP_LOGE(TAG, "Failed to open file for writing");
        //     break;
        //   }
        //   first_time = false;
        // }

        is_first = false;
        init_packet->header.seq = data->header.seq;
        memcpy(init_packet->body, &init_packet_body,
               sizeof(nw_security_initiator_packet_t));
        err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                          init_packet, init_len, &frame_head,
                          pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
        // unsigned long int ttt = esp_timer_get_time(); // start to measure

        ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                           esp_err_to_name(err));
        do {
          now = MILLIS();

          err = espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                            &rx_ctrl,
                            pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
          ESP_ERROR_CONTINUE(err != ESP_OK, "");
          if (data->header.type == NW_SECURITY_RESP_TYPE) {
            nw_security_response_packet_t *resp =
                (nw_security_response_packet_t *)data->body;
            if (memcmp(resp->addr, my_mac, ESPNOW_ADDR_LEN) == 0) {
              // unsigned long int ok = esp_timer_get_time();
              is_first = resp->is_first;
              pref = rx_ctrl.rssi - resp->value;
              rounds = data->header.seq;
              ESP_LOGW(TAG, "is_first %d , and pref : %d and round %d",
                       is_first, pref, rounds);
              // fprintf(sec_log, "%d," MACSTR ",%d,%d,%d,%d\n", rounds,
              //         MAC2STR(addr), rx_ctrl.rssi, is_first, pref,
              //         init_packet->header.seq);
              flag_rec = true;
              prefs_indexes[rounds] = data->header.seq;
              prefs[rounds] = pref;
              break;
            }
          }
        } while (!CHECK_TIMEOUT(base_time, now, 5 * NW_SECURITY_START_TIMEOUT));

        if (!flag_rec) {
          ESP_LOGE(TAG, "response is missing in seq:%d",
                   init_packet->header.seq);
          // fprintf(sec_log, "response is missing in seq:%d \r\n",
          //         init_packet->header.seq);
          init_packet_body.failed_index = init_packet->header.seq;
        } else {
          flag_rec = false;
          init_packet_body.failed_index = -1;
        }
      } else if (data->header.type == NW_SECURITY_FINISH_TYPE) {
        ESP_LOGI(TAG, "recv finish");
        break;
      } else {
        ESP_LOGI(TAG, "recv bowlshit");
      }
    }

    is_first = true;
  }
  if (nw_comm_sec.is_ch) {
    for (int i = 0; i < NW_SECURITY_FINISH_PACKET_NUMS; i++) {
      err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                        finish_packet, finish_len, &frame_head,
                        pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
      ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                         esp_err_to_name(err));
      vTaskDelay(pdMS_TO_TICKS(NW_SECURITY_FINISH_WAITH));
      ESP_LOGI(TAG, "send finish packet number %d", i);
    }
  }
  ESP_LOGW(TAG, "nw security finished %d", rounds);
  sec_log = fopen("/spiffs/seclog.txt", "w");
  ESP_ERROR_GOTO(sec_log == NULL, CLEAN, "Failed to open file for writing");

  // for (int i = 0; i < vector_len; i++) {
  //   fprintf(sec_log, "%d,%d\r\n", prefs_indexes[i], prefs[i]);
  // }
  // fclose(sec_log);
  /**
   * @brief  quantize rssi to 1 bit
   */

  quantized =
      local_mean_quantizer(prefs, vector_len, NW_SECURITY_LOCAL_QUANTIZE_VALUE);

  bch = init_bch(NW_SECURITY_BCH_M, NW_SECURITY_BCH_T, 0);
  random_mask_len = (bch->n - bch->ecc_bits) / 8; // rounds to lower bound

  cypher_len =
      bch->ecc_bits / 8 + (int)(bch->ecc_bits % 8 != 0) + random_mask_len;
  assert(cypher_len == sizeof(nw_security_key_start_packet_t));
  ESP_LOGW(TAG, "cypher len is %d", cypher_len);

  rounds = 0;
  internal_rounds = -1;
  random_mask = (uint8_t *)heap_caps_malloc(random_mask_len + bch->ecc_bytes,
                                            MALLOC_CAP_8BIT);

  err_loc = (uint32_t *)heap_caps_malloc(NW_SECURITY_BCH_T * sizeof(uint32_t),
                                         MALLOC_CAP_8BIT);

  flag_rec = false;
  while (rounds < vector_len / cypher_len) {
    int32_t base_time = MILLIS();

    if (nw_comm_sec.is_ch) {

      num_childs_counter = 0;

      key_start_packet->header.seq = rounds;
      memset(random_mask, 0, random_mask_len + bch->ecc_bytes);

      random_vector_generator(random_mask, random_mask_len);
      encode_bch(bch, random_mask, random_mask_len,
                 random_mask + random_mask_len);
      for (int i = 0; i < 16; i++) {
        key_start_packet_body.cypher[i] =
            quantized[rounds * 16 + i] ^ random_mask[i];
      }
      memcpy(key_start_packet->body, &key_start_packet_body,
              sizeof(nw_security_key_start_packet_t));

      crc_buffer = crc16(0xFFFF, quantized + rounds * 16, 16);
      err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                        key_start_packet, key_start_len, &frame_head,
                        pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
      ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                         esp_err_to_name(err));
      base_time = MILLIS();
      do {
        now = MILLIS();
        err =
            espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                        &rx_ctrl, pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
        ESP_ERROR_CONTINUE(err != ESP_OK, "");

        if (data->header.type == NW_SECURITY_KEY_RESPONSE_TYPE) {
          num_childs_counter++;
          ESP_LOGW(TAG, " received reponse, and seq %d and round %d",
                   data->header.seq, rounds);

          memcpy(&key_response_packet_body, data->body,
                 sizeof(nw_security_key_response_packet_t));

          if (key_response_packet_body.failed_index != -1 &&
              key_response_packet_body.failed_index < rounds) {
            if ((internal_rounds == -1) ||
                (internal_rounds != -1 &&
                 key_response_packet_body.failed_index < internal_rounds)) {
              internal_rounds = key_response_packet_body.failed_index;
              internal_final_index = key_response_packet_body.final_index;
            }
          }

          if (crc_buffer != key_response_packet_body.crc) {
            pass_round = false;
          }

          base_time = now;
        }

      } while (!CHECK_TIMEOUT(base_time, now, NW_SECURITY_START_TIMEOUT));

      if (num_childs != num_childs_counter) {
        ESP_LOGE(TAG, "some node is missing in seq:%d",
                 key_start_packet->header.seq);
        vTaskDelay(4 * NW_SECURITY_START_TIMEOUT);
        pass_round = false;
      } else {
        rounds++;
      }
      if (internal_rounds != -1) {
        ESP_LOGE(TAG, "some node reports missing in seq:%d", internal_rounds);
        rounds = internal_rounds;
        internal_rounds = -1;
        final_index = internal_final_index;
        pass_round = false;
        // vTaskDelay(4 * NW_SECURITY_START_TIMEOUT);
      }
      key_ack_packet->header.seq = key_start_packet->header.seq;
      key_ack_packet_body.ack = pass_round;
      memcpy(key_ack_packet->body, &key_ack_packet_body,
             sizeof(nw_security_key_ack_packet_t));
      err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                        key_ack_packet, key_ack_len, &frame_head,
                        pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
      ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                         esp_err_to_name(err));

      if (pass_round) {
        for (int i = 0; i < 16; i++) {
          final_vector[final_index + i] = quantized[rounds * 16 + i];
        }

        final_index += cypher_len;
      }

      pass_round = true;

    } else { // if is not ch

      err = espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                        &rx_ctrl, pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
      ESP_ERROR_CONTINUE(err != ESP_OK, "");

      if (data->header.type == NW_SECURITY_KEY_START_TYPE) {

        // xor cypher with its block
        memcpy(&key_start_packet_body, data->body,
               sizeof(nw_security_key_start_packet_t));
        rounds = data->header.seq;
        memset(random_mask, 0, random_mask_len + bch->ecc_bytes);
        memset(err_loc, 0, NW_SECURITY_BCH_T);
        for (int i = 0; i < cypher_len; i++) {
          random_mask[i] =
              quantized[rounds * 16 + i] ^ key_start_packet_body.cypher[i];
        }
        // bch decode and extract random mask
        decode_bch(bch, random_mask, random_mask_len,
                   random_mask + random_mask_len, NULL, NULL, err_loc);

        for (int i = 0; i < NW_SECURITY_BCH_T; i++) {
          if (err_loc[i] != 0) {
            random_mask[err_loc[i] / 8] ^= 1 << (err_loc[i] % 8);
          }
        }
        // xor cypher with its random mask
        for (int i = 0; i < cypher_len; i++) {

          final_vector[final_index + i] =
              random_mask[i] ^ key_start_packet_body.cypher[i];
        }
        // calc crc and send
        key_response_packet_body.crc =
            crc16(0xFFFF, final_vector + final_index, 16);

        key_reponse_packet->header.seq = data->header.seq;
        memcpy(key_reponse_packet->body, &key_response_packet_body,
               sizeof(nw_security_key_response_packet_t));
        err = espnow_send(ESPNOW_TYPE_SCPS_SEC, ESPNOW_ADDR_BROADCAST,
                          key_reponse_packet, key_response_len, &frame_head,
                          pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
        ESP_ERROR_CONTINUE(err != ESP_OK, "<%s> espnow_send",
                           esp_err_to_name(err));
        do {
          now = MILLIS();

          err = espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                            &rx_ctrl,
                            pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
          ESP_ERROR_CONTINUE(err != ESP_OK, "");
          if (data->header.type == NW_SECURITY_KEY_ACK_TYPE &&
              data->header.seq == key_reponse_packet->header.seq) {
            ESP_LOGW(TAG, "received ack");
            memcpy(&key_ack_packet_body, data->body,
                   sizeof(nw_security_key_ack_packet_t));
            flag_rec = true;

            if (key_ack_packet_body.ack) {

              final_index += cypher_len;
            }
            break;
          }
        } while (!CHECK_TIMEOUT(base_time, now, 5 * NW_SECURITY_START_TIMEOUT));

        if (!flag_rec) {
          ESP_LOGE(TAG, "response is missing in seq:%d",
                   key_reponse_packet->header.seq);
          // fprintf(sec_log, "response is missing in seq:%d \r\n",
          //         init_packet->header.seq);
          key_response_packet_body.failed_index =
              key_reponse_packet->header.seq;
          key_response_packet_body.final_index = final_index;
        } else {
          flag_rec = false;
          key_response_packet_body.failed_index = -1;
          key_response_packet_body.final_index = -1;
        }
      } else if (data->header.type == NW_SECURITY_FINISH_TYPE) {
        ESP_LOGI(TAG, "recv finish");
        break;
      } else {
        ESP_LOGI(TAG, "recv bowlshit");
      }
    }
  }
  free(quantized);
CLEAN:
  sec_log = NULL;
  free(resp_packet);
  free(data);
  free(start_packet);
  vTaskDelete(NULL);
}

static void nw_eve_task(void *params) {

  uint8_t my_mac[ESPNOW_ADDR_LEN] = {0};
  ESP_ERROR_CHECK(esp_read_mac(my_mac, ESP_MAC_WIFI_STA));
  esp_err_t err = ESP_OK;
  size_t size = ESPNOW_DATA_LEN;
  nw_packet_t *data =
      (nw_packet_t *)heap_caps_malloc(ESPNOW_DATA_LEN, MALLOC_CAP_8BIT);
  uint8_t addr[ESPNOW_ADDR_LEN] = {0};
  wifi_pkt_rx_ctrl_t rx_ctrl = {0};
  espnow_frame_head_t frame_head = {
      .broadcast = true,
      .retransmit_count = 10,
  };
  bool is_first = true;
  bool wait_for_response = false;
  int len = sizeof(nw_packet_t) + sizeof(nw_security_start_packet_t);
  int resp_len = sizeof(nw_packet_t) + sizeof(nw_security_response_packet_t);
  int init_len = sizeof(nw_packet_t) + sizeof(nw_security_initiator_packet_t);

  nw_packet_t *resp_packet =
      (nw_packet_t *)heap_caps_malloc(resp_len, MALLOC_CAP_DEFAULT);
  nw_packet_t *init_packet =
      (nw_packet_t *)heap_caps_malloc(init_len, MALLOC_CAP_DEFAULT);
  init_packet->header.seq = 0;
  init_packet->header.size = sizeof(nw_security_initiator_packet_t);
  init_packet->header.type = NW_SECURITY_INIT_TYPE;

  nw_security_response_packet_t resp_packet_body = {};
  int8_t prefs = 0;
  int32_t now = 0;
  bool flag = false;
  int8_t rounds = 10;
  ESP_LOGI(TAG, "nw_eve start");

  while (true) {

    err = espnow_recv(ESPNOW_TYPE_SCPS_SEC, addr, (uint8_t *)data, &size,
                      &rx_ctrl, pdMS_TO_TICKS(NW_SECURITY_START_BC_TIMEOUT));
    ESP_ERROR_CONTINUE(err != ESP_OK, "");
    if (first_time) {
      sec_log = fopen("/spiffs/seclog.txt", "w");
      if (sec_log == NULL) {
        ESP_LOGE(TAG, "Failed to open file for writing");
        break;
      }
      first_time = false;
    }
    if (data->header.type == NW_SECURITY_RESP_TYPE) {
      nw_security_response_packet_t *resp =
          (nw_security_response_packet_t *)data->body;
      is_first = resp->is_first;
      ESP_LOGW(TAG, MACSTR ",%d,%d,%d,%d\n", MAC2STR(addr), rx_ctrl.rssi,
               is_first, resp->value, data->header.seq);
      fprintf(sec_log, MACSTR ",%d,%d,%d,%d\n", MAC2STR(addr), rx_ctrl.rssi,
              is_first, resp->value, data->header.seq);

    } else if (data->header.type == NW_SECURITY_INIT_TYPE) {
      ESP_LOGW(TAG, MACSTR ",%d,%d\n", MAC2STR(addr), rx_ctrl.rssi,
               data->header.seq);

      fprintf(sec_log, MACSTR ",%d,%d\n", MAC2STR(addr), rx_ctrl.rssi,
              data->header.seq);
    }
  }
  fclose(sec_log);
  free(resp_packet);
  free(data);
  vTaskDelete(NULL);
}

static esp_err_t start_spiffs() {
  esp_vfs_spiffs_conf_t conf = {.base_path = "/spiffs",
                                .partition_label = NULL,
                                .max_files = 5,
                                .format_if_mount_failed = true};

  // Use settings defined above to initialize and mount SPIFFS filesystem.
  // Note: esp_vfs_spiffs_register is an all-in-one convenience function.
  esp_err_t ret = esp_vfs_spiffs_register(&conf);

  if (ret != ESP_OK) {
    if (ret == ESP_FAIL) {
      ESP_LOGE(TAG, "Failed to mount or format filesystem");
    } else if (ret == ESP_ERR_NOT_FOUND) {
      ESP_LOGE(TAG, "Failed to find SPIFFS partition");
    } else {
      ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
    }
    return ESP_FAIL;
  }

  size_t total = 0, used = 0;
  ret = esp_spiffs_info(conf.partition_label, &total, &used);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)",
             esp_err_to_name(ret));
  } else {
    ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
  }

  return ESP_OK;
}

esp_err_t nw_security_assign_ch(bool is_ch) {
  nw_comm_sec.is_ch = is_ch;
  ESP_LOGW(TAG, "is ch ? %d", nw_comm_sec.is_ch);
  return ESP_OK;
}

esp_err_t nw_security_eve_start() {
  ESP_ERROR_CHECK(start_spiffs());
  nw_comm_sec.is_ch = false;

  xTaskCreatePinnedToCore(nw_eve_task, "nw_sec", 4 * 1024, NULL, 1, NULL, 0);
  return ESP_OK;
}

esp_err_t nw_security_start() {

  ESP_ERROR_CHECK(start_spiffs());
  nw_comm_sec.is_ch = false;

  xTaskCreatePinnedToCore(nw_security_task, "nw_sec", 5 * 1024, NULL, 1, NULL,
                          0);

  return ESP_OK;
}

void reading_logs() {
  if (sec_log != NULL) {
    fclose(sec_log);
  }
  std::cout << "log with cout \r\n";

  std::ifstream read_file("/spiffs/seclog.txt");
  std::string line;
  if (read_file.is_open()) {
    while (std::getline(read_file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    ESP_LOGE(TAG, "error on reading file");
  }
  ESP_LOGI(TAG, "end of printing");
}
