//  SPDX-License-Identifier: MIT

#include <string.h>

#include "esp_log.h"

#include "ieee802154.h"

#define TAG "ieee802154"

static void reverse_memcpy(uint8_t *restrict dst, const uint8_t *restrict src, size_t n);

uint8_t ieee802154_header(const uint16_t *src_pan, ieee802154_address_t *src, const uint16_t *dst_pan, ieee802154_address_t *dst, uint8_t *header, uint8_t header_length) {
    uint8_t frame_header_len = 2;
    mac_fcs_t frame_header = {
            .frameType = FRAME_TYPE_DATA,
            .secure = false,
            .framePending = false,
            .ackReqd = false,
            .panIdCompressed = false,
            .rfu1 = false,
            .sequenceNumberSuppression = false,
            .informationElementsPresent = false,
            .destAddrType = dst->mode,
            .frameVer = FRAME_VERSION_STD_2003,
            .srcAddrType = src->mode
    };

    bool src_present = src != NULL && src->mode != ADDR_MODE_NONE;
    bool dst_present = dst != NULL && dst->mode != ADDR_MODE_NONE;
    bool src_pan_present = src_pan != NULL;
    bool dst_pan_present = dst_pan != NULL;

    if (src_pan_present && dst_pan_present && src_present && dst_present) {
        if (src_pan == dst_pan) {
            frame_header.panIdCompressed = true;
        }
    }

    if (!frame_header.sequenceNumberSuppression) {
        frame_header_len += 1;
    }

    if (dst_pan_present) {
        frame_header_len += 2;
    }

    if (frame_header.destAddrType == ADDR_MODE_SHORT) {
        frame_header_len += 2;
    } else if (frame_header.destAddrType == ADDR_MODE_LONG) {
        frame_header_len += 8;
    }

    if (src_pan_present && !frame_header.panIdCompressed) {
        frame_header_len +=2;
    }

    if (frame_header.srcAddrType == ADDR_MODE_SHORT) {
        frame_header_len += 2;
    } else if (frame_header.srcAddrType == ADDR_MODE_LONG) {
        frame_header_len += 8;
    }

    if (header_length < frame_header_len) {
        return 0;
    }

    uint8_t position = 0;
    memcpy(&header[position], &frame_header, sizeof frame_header);
    position += 2;

    if (!frame_header.sequenceNumberSuppression) {
        header[position++] = 0;
    }

    if (dst_pan != NULL) {
        memcpy(&header[position], dst_pan, sizeof(uint16_t));
        position += 2;
    }

    if (frame_header.destAddrType == ADDR_MODE_SHORT) {
        memcpy(&header[position], &dst->short_address, sizeof dst->short_address);
        position += 2;
    } else if (frame_header.destAddrType == ADDR_MODE_LONG) {
        reverse_memcpy(&header[position], (uint8_t *)&dst->long_address, sizeof dst->long_address);
        position += 8;
    }

    if (src_pan != NULL && !frame_header.panIdCompressed) {
        memcpy(&header[position], src_pan, sizeof(uint16_t));
        position += 2;
    }

    if (frame_header.srcAddrType == ADDR_MODE_SHORT) {
        memcpy(&header[position], &src->short_address, sizeof src->short_address);
        position += 2;
    } else if (frame_header.srcAddrType == ADDR_MODE_LONG) {
        reverse_memcpy(&header[position], (uint8_t *)&src->long_address, sizeof src->long_address);
        position += 8;
    }

    return position;
}

static void reverse_memcpy(uint8_t *restrict dst, const uint8_t *restrict src, size_t n)
{
    size_t i;

    for (i=0; i < n; ++i) {
        dst[n - 1 - i] = src[i];
    }
}