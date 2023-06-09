//
// Created by Hugo Trippaers on 09/06/2023.
//
// Copied from https://github.com/atc1441/ZBS_Flasher/blob/main/custom-firmware/firmware_ch11_low_power/drawing.c
//

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "esp_log.h"

#define COMPRESSION_BITPACKED_3x5_to_7 0x62700357 // 3 pixels of 5 possible colors in 7 bits
#define COMPRESSION_BITPACKED_5x3_to_8 0x62700538 // 5 pixels of 3 possible colors in 8 bits
#define COMPRESSION_BITPACKED_3x6_to_8 0x62700368 // 3 pixels of 6 possible colors in 8 bits

#define SCREEN_WIDTH				128
#define SCREEN_HEIGHT				296

#define TAG "verify_bitmap"

struct BitmapFileHeader
{
    uint8_t sig[2];
    uint32_t fileSz;
    uint8_t rfu[4];
    uint32_t dataOfst;
    uint32_t headerSz; // 40
    int32_t width;
    int32_t height;
    uint16_t colorplanes; // must be one
    uint16_t bpp;
    uint32_t compression;
    uint32_t dataLen; // may be 0
    uint32_t pixelsPerMeterX;
    uint32_t pixelsPerMeterY;
    uint32_t numColors; // if zero, assume 2^bpp
    uint32_t numImportantColors;
} __attribute__((packed, aligned(1)));

struct BitmapDrawInfo
{
    // dimensions
    uint16_t w, h, effectiveW, effectiveH, stride /* 0 -> 1, 5 - >7, 255 -> 256 */;
    uint8_t numColorsM1;

    // data start
    uint32_t dataAddr;

    // compression state
    uint8_t packetPixelDivVal;
    uint8_t packetNumPixels;
    uint8_t packetBitSz;
    uint8_t packetBitMask; // derived from the above

    // flags
    uint8_t bpp : 4;
    uint8_t bottomUp : 1;
};


uint32_t verify_bitmap(const uint8_t *bitmap)
{
    struct BitmapDrawInfo mDrawInfo;
    struct BitmapFileHeader bmph;
    uint16_t packetsPerRow;
    uint32_t compression;

    memcpy(&bmph, bitmap, (sizeof(bmph)));

    ESP_LOGI(TAG, "SIG              : %c%c", bmph.sig[0], bmph.sig[1]);
    ESP_LOGI(TAG, "Filesize         : %lu", bmph.fileSz);
    ESP_LOGI(TAG, "Dataoffset       : %lu", bmph.dataOfst);
    ESP_LOGI(TAG, "HeaderSize       : %lu", bmph.headerSz);
    ESP_LOGI(TAG, "Resolution (wxh) : %lu x %lu", bmph.width, bmph.height);
    ESP_LOGI(TAG, "Dataoffset       : %lu", bmph.dataOfst);
    ESP_LOGI(TAG, "Colorplanes      : %d", bmph.colorplanes);
    ESP_LOGI(TAG, "BPP              : %d", bmph.bpp);
    ESP_LOGI(TAG, "Compression      : %08lx", bmph.compression);
    ESP_LOGI(TAG, "Data Length      : %lu", bmph.dataLen);
    ESP_LOGI(TAG, "px/m X           : %lu", bmph.pixelsPerMeterX);
    ESP_LOGI(TAG, "px/m Y           : %lu", bmph.pixelsPerMeterY);
    ESP_LOGI(TAG, "colors           : %lu", bmph.numColors);
    ESP_LOGI(TAG, "important colors : %lu", bmph.numImportantColors);


    if (bmph.sig[0] != 'B' || bmph.sig[1] != 'M') {
        ESP_LOGW(TAG, "missing BMP header");
        return 0;
    }

    if (bmph.colorplanes != 1) {
        ESP_LOGW(TAG, "color planes should be 1, but is %d", bmph.colorplanes);
        return 0;
    }

    if (bmph.headerSz < 40) {  // < 40
        ESP_LOGW(TAG, "header size <40");
        return 0;
    }

    if (bmph.bpp > 8) {
        ESP_LOGW(TAG, "bpp > 8");
        return 0;
    }
    mDrawInfo.bpp = bmph.bpp;

    if (bmph.headerSz >= 257) {  // >= 257
        ESP_LOGW(TAG, "header size >=257");
        return 0;
    }

    if (bmph.numColors != 0)
        mDrawInfo.numColorsM1 = (uint8_t)bmph.numColors - (uint8_t)1;
    else
        mDrawInfo.numColorsM1 = (uint8_t)((uint8_t)1 << (uint8_t)mDrawInfo.bpp) - (uint8_t)1;

    if (bmph.height == 0) {
        ESP_LOGW(TAG, "height = 0");
        return 0;
    }

    if (bmph.width == 0 || bmph.width > 0xffff) {
        ESP_LOGW(TAG, "bmph.width == 0 || bmph.width > 0xffff");
        return 0;
    }

    mDrawInfo.w = bmph.width;

    if (bmph.height < 0)
    {
        if ((bmph.height + 0xffff) < 0)
            goto fail;
        mDrawInfo.h = -bmph.height;
        mDrawInfo.bottomUp = false;
    }
    else
    {
        if (bmph.headerSz > 0xffff)
            goto fail;
        mDrawInfo.h = bmph.height;
        mDrawInfo.bottomUp = true;
    }

    compression = bmph.compression;
    if (compression == COMPRESSION_BITPACKED_3x5_to_7 || compression == COMPRESSION_BITPACKED_5x3_to_8 || compression == COMPRESSION_BITPACKED_3x6_to_8)
    {

        mDrawInfo.packetNumPixels = (uint8_t)(compression >> 8) & 0x0f;
        mDrawInfo.packetBitSz = (uint8_t)compression & 0x0f;
        mDrawInfo.packetPixelDivVal = ((uint8_t)compression) >> 4;
    }
    else if (bmph.compression)
    {

        ESP_LOGW("bitmap", "unknown compression 0x%08lx", bmph.compression);
        goto fail;
    }
    else
    { // uncompressed

        mDrawInfo.packetPixelDivVal = 0;
        mDrawInfo.packetNumPixels = 1;
        mDrawInfo.packetBitSz = mDrawInfo.bpp;
    }
    packetsPerRow = (mDrawInfo.w + mDrawInfo.packetNumPixels - 1) /  mDrawInfo.packetNumPixels;
    mDrawInfo.stride = (packetsPerRow * mDrawInfo.packetBitSz + 31 /  32) * 4UL;
    mDrawInfo.packetBitMask = (uint8_t)(((uint8_t)1) << (uint8_t)mDrawInfo.packetBitSz) - (uint8_t)1;

    // calc effective size
    mDrawInfo.effectiveH = (mDrawInfo.h > SCREEN_HEIGHT) ? SCREEN_HEIGHT : mDrawInfo.h;
    mDrawInfo.effectiveW = (mDrawInfo.w > SCREEN_WIDTH) ? SCREEN_WIDTH : mDrawInfo.w;

    return 1;
fail:
    return 0;
}