//
// Created by Hugo Trippaers on 05/06/2023.
//

#include <string.h>

#include "esp_log.h"
#include "mbedtls/ccm.h"

#include "esp_esl.h"

#define AES_CCM_NONCE_SIZE 13
uint8_t  esl_key[] = {0xD3, 0x06, 0xD9, 0x34, 0x8E, 0x29, 0xE5, 0xE3, 0x58, 0xBF, 0x29, 0x34, 0x81, 0x20, 0x02, 0xC1};

static mbedtls_ccm_context ctx;

#define TAG "esp_esl"

/// \brief Initializes the aes_ccm context for encrypting and decrypting frames
///
/// \return ESP_OK on success, ESP_FAIL on failure
esp_err_t esp_esl_aes_ccm_init() {
    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, esl_key, sizeof(esl_key) * 8);

    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ccm_setkey failed, rc = %d", ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/// \brief Encrypts a shelf label packet with AES_CCM
///
/// \param timestamp The timestamp part of the nonce
/// \param plaintext The unencrypted payload of the frame
/// \param plaintext_length The size of the payload
/// \param header The IEEE802.15.4 header
/// \param header_length The size of the header
/// \param src_addr Source address of the frame
/// \param output A buffer where the encrypted can be stored
/// \param output_length The maximum size of the buffer, should be big enough to store payload, timestamp and tag
/// \return The actual size of the payload stored in the buffer
uint8_t esp_esl_aes_ccm_encode(uint32_t timestamp, uint8_t* plaintext, uint8_t plaintext_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *output, uint8_t output_length) {
    uint8_t timestamp_length = 4;
    uint8_t tag_length = 4;

    if (output == NULL) {
        ESP_LOGE(TAG, "Invalid output buffer");
        return 0;
    }

    if (output_length < plaintext_length + timestamp_length + tag_length) {
        ESP_LOGE(TAG, "output buffer too small");
        return 0;
    }

    uint8_t nonce[AES_CCM_NONCE_SIZE] = {0};

    // Nonce: | timestamp (4 bytes) | source addr (8 bytes) | 0 (1 byte) |
    memcpy(nonce, &timestamp, timestamp_length);
    for (uint8_t idx = 0; idx < 8; idx++) {
        nonce[4 + idx] = src_addr[7 - idx];
    }

    int ret = mbedtls_ccm_encrypt_and_tag(&ctx, plaintext_length,
                                          nonce, AES_CCM_NONCE_SIZE,
                                          header, header_length,
                                          plaintext, output,
                                          output + plaintext_length, tag_length);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to encrypt packet, rc = %d", ret);
        return 0;
    }

    ESP_LOGD(TAG, "Nonce:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, nonce, AES_CCM_NONCE_SIZE, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Tag:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, output + plaintext_length, tag_length, ESP_LOG_DEBUG);

    // Insert the timestamp into the buffer
    memcpy(output+plaintext_length+tag_length, &timestamp, timestamp_length);

    // Return the length
    return plaintext_length + timestamp_length + tag_length;
}

/// \brief decode an shelf label packet encrypted and tagged
///
/// \param payload the payload to be decrypted, the payload includes the timestamp and tag
/// \param payload_length the size of the payload including the timestamp and tag
/// \param header the frame header
/// \param header_length the frame header size
/// \param src_addr the source address of the frame
/// \param plaintext output parameter, the buffer to hold the decrypted payload
/// \param plaintext_length the size of the output buffer
/// \return the actual size of the plaintext buffer or 0 on error
uint8_t esp_esl_aes_ccm_decode(uint8_t *payload, uint8_t payload_length, uint8_t *header, uint8_t header_length,
                               const uint8_t *src_addr, uint8_t *plaintext, uint8_t plaintext_length) {
    uint8_t timestamp_length = 4;
    uint8_t tag_length = 4;

    if (plaintext == NULL) {
        ESP_LOGE(TAG, "Invalid plaintext buffer");
        return 0;
    }

    if (plaintext_length < plaintext_length - (timestamp_length + tag_length)) {
        ESP_LOGE(TAG, "output buffer too small");
        return 0;
    }

    uint8_t nonce[AES_CCM_NONCE_SIZE] = {0};

    // last four bytes is the timestamp
    // second to last four bytes is the tag
    uint8_t data_length = payload_length - timestamp_length - tag_length;
    uint8_t *timestamp = payload + data_length;
    uint8_t *tag = payload + data_length + timestamp_length;

    // Nonce: | timestamp (4 bytes) | source addr (8 bytes) | 0 (1 byte) |
    memcpy(nonce, &timestamp, timestamp_length);
    for (uint8_t idx = 0; idx < 8; idx++) {
        nonce[4 + idx] = src_addr[7 - idx];
    }

    ESP_LOGD(TAG, "Nonce:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, nonce, AES_CCM_NONCE_SIZE, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Tag:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, tag, tag_length, ESP_LOG_DEBUG);

    int ret = mbedtls_ccm_auth_decrypt(&ctx, payload_length,
                                       nonce, AES_CCM_NONCE_SIZE,
                                       header, header_length,
                                       payload, plaintext,
                                       tag, tag_length);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to decrypt packet, rc = %d", ret);
        return 0;
    }
    return data_length;
}

