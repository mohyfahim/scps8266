#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /**< _cplusplus */

typedef enum {
  NW_CREATION_BEACON_TYPE,
  NW_DISCOVERY_START_TYPE,
  NW_DISCOVERY_GRAPH_TYPE,
  NW_SECURITY_START_TYPE,
  NW_SECURITY_INIT_TYPE,
  NW_SECURITY_RESP_TYPE,
  NW_SECURITY_FINISH_TYPE,
  NW_SECURITY_KEY_START_TYPE,
  NW_SECURITY_KEY_RESPONSE_TYPE,
  NW_SECURITY_KEY_ACK_TYPE,
  NW_DATA_TYPE,
  NW_DATA_IR_TYPE,
  NW_SYS_CONFIG_TYPE,
  NW_ROUTINE_CONFIG_TYPE,
} nw_packet_type_t;

typedef struct {
  uint8_t type;
  uint16_t seq;
  uint8_t size;

} __attribute__((packed)) nw_packet_header_t;

typedef struct {
  nw_packet_header_t header;
  uint8_t body[0];
} __attribute__((packed)) nw_packet_t;

typedef struct {
  int ttl;
} __attribute__((packed)) nw_discovery_start_packet_t;

typedef struct {
} __attribute__((packed)) nw_security_start_packet_t;

typedef struct {
} __attribute__((packed)) nw_security_finish_packet_t;

typedef struct {
  int failed_index;
} __attribute__((packed)) nw_security_initiator_packet_t;

typedef struct {
  bool is_first;
  int8_t value;
  uint8_t addr[6];
} __attribute__((packed)) nw_security_response_packet_t;

typedef struct {
  int8_t rssi;
  uint8_t addr[6];
} __attribute__((packed)) nw_mdf_graph_table_packet_t;

typedef struct {
  uint8_t cypher[16];
} __attribute__((packed)) nw_security_key_start_packet_t;

typedef struct {
  int failed_index;
  int final_index;
  uint16_t crc;
} __attribute__((packed)) nw_security_key_response_packet_t;

typedef struct {
  bool ack;
} __attribute__((packed)) nw_security_key_ack_packet_t;

typedef struct {
  uint8_t NumberOfHVAC;
  uint8_t NumberOfFanAir;
  uint8_t HVACType;
} __attribute__((packed)) nw_data_init_packet_t;

#ifdef __cplusplus
}
#endif /**< _cplusplus */
