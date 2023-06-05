//
// Created by Hugo Trippaers on 05/06/2023.
//

#ifndef IEEE802154_SENDER_ESP_ESL_H
#define IEEE802154_SENDER_ESP_ESL_H

#include <esp_err.h>

esp_err_t esp_esl_aes_ccm_init();
uint8_t esp_esl_aes_ccm_encode(uint32_t timestamp, uint8_t* plaintext, uint8_t plaintext_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *output, uint8_t output_length);
uint8_t esp_esl_aes_ccm_decode(uint8_t* payload, uint8_t payload_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *plaintext, uint8_t plaintext_length);

#endif //IEEE802154_SENDER_ESP_ESL_H
