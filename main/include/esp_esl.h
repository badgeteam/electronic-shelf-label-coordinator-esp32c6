//  SPDX-License-Identifier: MIT

#ifndef IEEE802154_SENDER_ESP_ESL_H
#define IEEE802154_SENDER_ESP_ESL_H

#include <esp_err.h>

#include "esl_proto.h"

typedef struct esl_packet {
    uint8_t  packet_type;
    uint8_t  source_addr[8];
    uint8_t  dest_addr[8];
    uint16_t data_length;
    union {
        uint8_t             raw[256];            // Should be enough space for the flexible arrays
        struct TagInfo      tag_info;            // PKT_ASSOC_REQ
        struct AssocInfo    assoc_info;          // PKT_ASSOC_RESP
        struct CheckinInfo  check_in_info;       // PKT_CHECKIN
        struct PendingInfo  pending_info;        // PKT_CHECKOUT
        struct ChunkReqInfo chunk_request_info;  // PKT_CHUNK_REQ
        struct ChunkInfo    chunk_info;          // PKT_CHUNK_RESP
    };
} __attribute__((packed, aligned(1))) esl_packet_t;

esp_err_t esp_esl_aes_ccm_init();
uint8_t esp_esl_aes_ccm_encode(uint32_t timestamp, uint8_t* plaintext, uint8_t plaintext_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *output, uint8_t output_length);
uint8_t esp_esl_aes_ccm_decode(uint8_t* payload, uint8_t payload_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *plaintext, uint8_t plaintext_length);

void esp_esl_packet_log(esl_packet_t *packet);
#endif //IEEE802154_SENDER_ESP_ESL_H
