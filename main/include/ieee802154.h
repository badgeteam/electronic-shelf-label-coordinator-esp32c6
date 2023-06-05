//
// Created by Hugo Trippaers on 02/06/2023.
//

#ifndef EPD_STATION_IEEE802154_H
#define EPD_STATION_IEEE802154_H

#include "freertos/FreeRTOS.h"
#include "802154_proto.h"

typedef struct {
    uint8_t mode; // ADDR_MODE_NONE || ADDR_MODE_SHORT || ADDR_MODE_LONG
    union {
        uint16_t short_address;
        uint8_t long_address[8];
    };
} ieee802154_address_t ;

uint8_t iee802154_header(const uint16_t *src_pan, ieee802154_address_t *src, const uint16_t *dst_pan, ieee802154_address_t *dst, uint8_t *header, uint8_t header_length);

#endif  // EPD_STATION_IEEE802154_H
