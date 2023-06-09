//
// Created by Hugo Trippaers on 05/06/2023.
//

#include <string.h>

#include "esp_log.h"
#include "mbedtls/ccm.h"

#include "esp_esl.h"

#define TIMESTAMP_LENGTH 4
#define TAG_LENGTH 4

#define AES_CCM_NONCE_SIZE 13

#define TAG "esp_esl"

// TODO Make this configurable
uint8_t  esl_key[] = {
    0xD3, 0x06, 0xD9, 0x34, 0x8E, 0x29, 0xE5, 0xE3,
    0x58, 0xBF, 0x29, 0x34, 0x81, 0x20, 0x02, 0xC1
};

static mbedtls_ccm_context ctx;

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
/// \return The actual size of the payload stored in the buffer or 0 on error
uint8_t esp_esl_aes_ccm_encode(uint32_t timestamp, uint8_t* plaintext, uint8_t plaintext_length, uint8_t* header, uint8_t header_length, const uint8_t* src_addr, uint8_t *output, uint8_t output_length) {
    if (output == NULL) {
        ESP_LOGE(TAG, "Invalid output buffer");
        return 0;
    }

    if (output_length < plaintext_length + TIMESTAMP_LENGTH + TAG_LENGTH) {
        ESP_LOGE(TAG, "output buffer too small");
        return 0;
    }

    uint8_t nonce[AES_CCM_NONCE_SIZE] = {0};

    // Nonce: | timestamp (4 bytes) | source addr (8 bytes) | 0 (1 byte) |
    memcpy(nonce, &timestamp, TIMESTAMP_LENGTH);
    for (uint8_t idx = 0; idx < 8; idx++) {
        nonce[4 + idx] = src_addr[7 - idx];
    }

    ESP_LOGD(TAG, "Nonce:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, nonce, AES_CCM_NONCE_SIZE, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Plaintext:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, plaintext, plaintext_length, ESP_LOG_DEBUG);

    int ret = mbedtls_ccm_encrypt_and_tag(&ctx, plaintext_length,
                                          nonce, AES_CCM_NONCE_SIZE,
                                          header, header_length,
                                          plaintext, output,
                                          output + plaintext_length, TAG_LENGTH);

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to encrypt packet, rc = %d", ret);
        return 0;
    }

    ESP_LOGD(TAG, "Tag:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, output + plaintext_length, TAG_LENGTH, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Encrypted:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, output, plaintext_length, ESP_LOG_DEBUG);

    // Insert the timestamp into the buffer
    memcpy(output + plaintext_length + TAG_LENGTH, &timestamp, TIMESTAMP_LENGTH);

    // Return the length
    return plaintext_length + TIMESTAMP_LENGTH + TAG_LENGTH;
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
    if (plaintext == NULL) {
        ESP_LOGE(TAG, "Invalid plaintext buffer");
        return 0;
    }

    if (plaintext_length < plaintext_length - (TIMESTAMP_LENGTH + TAG_LENGTH)) {
        ESP_LOGE(TAG, "output buffer too small");
        return 0;
    }

    uint8_t nonce[AES_CCM_NONCE_SIZE] = {0};

    // last four bytes is the timestamp
    // second to last four bytes is the tag
    uint8_t data_length = payload_length - TAG_LENGTH - TIMESTAMP_LENGTH;
    uint8_t *tag = payload + data_length;
    uint8_t *timestamp = payload + data_length + TAG_LENGTH;

    // Nonce: | timestamp (4 bytes) | source addr (8 bytes) | 0 (1 byte) |
    memcpy(nonce, timestamp, TIMESTAMP_LENGTH);
    for (uint8_t idx = 0; idx < 8; idx++) {
        nonce[4 + idx] = src_addr[7 - idx];
    }

    ESP_LOGD(TAG, "Nonce:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, nonce, AES_CCM_NONCE_SIZE, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Tag:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, tag, TAG_LENGTH, ESP_LOG_DEBUG);

    ESP_LOGD(TAG, "Encrypted:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, payload, payload_length, ESP_LOG_DEBUG);

    int ret = mbedtls_ccm_auth_decrypt(&ctx, data_length,
                                       nonce, AES_CCM_NONCE_SIZE,
                                       header, header_length,
                                       payload, plaintext,
                                       tag, TAG_LENGTH);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to decrypt packet, rc = %d", ret);
        return 0;
    }

    ESP_LOGD(TAG, "Plaintext:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, plaintext, plaintext_length, ESP_LOG_DEBUG);

    return data_length;
}

void esp_esl_packet_log(esl_packet_t *packet) {
    uint8_t* src_addr = packet->source_addr;
    uint8_t* dst_addr = packet->dest_addr;
    ESP_LOGI(TAG, "[%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X] to [%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X]: ", src_addr[0], src_addr[1], src_addr[2],
             src_addr[3], src_addr[4], src_addr[5], src_addr[6], src_addr[7], dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5],
             dst_addr[6], dst_addr[7]);

    switch (packet->packet_type) {
        case PKT_ASSOC_REQ:
            {
                struct TagInfo* tagInfo = &packet->tag_info;
                ESP_LOGI(TAG,
                         "Assoc request  proto v%u, sw v%llu, hw %04x, batt %u mV, w %u px (%u mm), h %u px (%u mm), c %04x, maxWait %u ms, screenType %u",
                         tagInfo->protoVer, tagInfo->state.swVer, tagInfo->state.hwType, tagInfo->state.batteryMv, tagInfo->screenPixWidth,
                         tagInfo->screenMmWidth, tagInfo->screenPixHeight, tagInfo->screenMmHeight, tagInfo->compressionsSupported, tagInfo->maxWaitMsec,
                         tagInfo->screenType);
                break;
            }
        case PKT_ASSOC_RESP:
            {
                struct AssocInfo* assocInfo = &packet->assoc_info;
                ESP_LOGI(
                    TAG,
                    "Assoc response: checkin delay %lu, retry delay %lu, failedCheckinsTillBlank %u, failedCheckinsTillDissoc %u, newKey %08lx %08lx %08lx "
                    "%08lx",
                    assocInfo->checkinDelay, assocInfo->retryDelay, assocInfo->failedCheckinsTillBlank, assocInfo->failedCheckinsTillDissoc,
                    assocInfo->newKey[0], assocInfo->newKey[1], assocInfo->newKey[2], assocInfo->newKey[3]);
                break;
            }
        case PKT_CHECKIN:
            {
                struct CheckinInfo* checkinInfo = &packet->check_in_info;
                ESP_LOGI(TAG, "Checkin: sw v%llu, hw %04x, batt %u mV, LQI %u, RSSI %d, temperature %u *c", checkinInfo->state.swVer,
                         checkinInfo->state.hwType, checkinInfo->state.batteryMv, checkinInfo->lastPacketLQI, checkinInfo->lastPacketRSSI,
                         checkinInfo->temperature - CHECKIN_TEMP_OFFSET);
                break;
            }
        case PKT_CHECKOUT:
            {
                struct PendingInfo* pendingInfo = &packet->pending_info;
                ESP_LOGI(TAG, "Checkout: image version %llu, image size %lu, os version %llu, os size %lu", pendingInfo->imgUpdateVer,
                         pendingInfo->imgUpdateSize, pendingInfo->osUpdateVer, pendingInfo->osUpdateSize);
                break;
            }
        case PKT_CHUNK_REQ:
            {
                struct ChunkReqInfo* chunkReqInfo = &packet->chunk_request_info;
                ESP_LOGI(TAG, "Chunk request: version %llu, offset %lu, len %u, os update %s", chunkReqInfo->versionRequested, chunkReqInfo->offset,
                         chunkReqInfo->len, chunkReqInfo->osUpdatePlz ? "yes" : "no");
                break;
            }
        case PKT_CHUNK_RESP:
            {
                struct ChunkInfo* chunkInfo = &packet->chunk_info;
                ESP_LOGI(TAG, "Chunk response: offset %lu, os update %s, ", chunkInfo->offset, chunkInfo->osUpdatePlz ? "yes" : "no");
                // for (uint8_t idx = 0; idx < sizeof(struct ChunkInfo); idx++) {
                //     printf("%02x", chunkInfo->data[idx]);
                // }
                break;
            }
        default:
            {
                ESP_LOGI(TAG, "Unknown ESL packet type (%u)", packet->packet_type);
            }
    }
}

