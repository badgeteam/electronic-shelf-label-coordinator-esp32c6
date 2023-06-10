#pragma once

#define PKT_ASSOC_REQ  (0xF0)
#define PKT_ASSOC_RESP (0xF1)
#define PKT_CHECKIN    (0xF2)
#define PKT_CHECKOUT   (0xF3)
#define PKT_CHUNK_REQ  (0xF4)
#define PKT_CHUNK_RESP (0xF5)

#define PROTO_VER_0              (0)
#define PROTO_VER_CURRENT        (PROTO_VER_0)
#define PROTO_COMPR_TYPE_LZ      (0x0001)
#define PROTO_COMPR_TYPE_BITPACK (0x0002)
#define PROTO_MAX_DL_LEN         (88)

enum TagScreenType {
    TagScreenEink_BW_1bpp = 0,
    TagScreenEink_BW_2bpp,
    TagScreenEink_BW_4bpp,
    TagScreenEink_BWY_only,  // 2bpp, but only 3 colors (BW?Y)
    TagScreenEink_BWY_2bpp,
    TagScreenEink_BWY_4bpp,
    TagScreenEink_BWR_only,  // 2bpp, but only 3 colors (BW?R)
    TagScreenEink_BWR_2bpp,
    TagScreenEink_BWR_4bpp,
    TagScreenEink_BWY_3bpp,
    TagScreenEink_BWR_3bpp,
    TagScreenEink_BW_3bpp,
    TagScreenPersistentLcd_1bpp,
    TagScreenEink_BWY_5colors,
    TagScreenEink_BWR_5colors,
    TagScreenEink_BWY_6colors,
    TagScreenEink_BWR_6colors,
    TagScreenTypeOther = 0x7f,
};

struct TagState {
    uint64_t swVer;
    uint16_t hwType;
    uint16_t batteryMv;
} __attribute__((packed, aligned(1)));

struct TagInfo {               // PKT_ASSOC_REQ
    uint8_t         protoVer;  // PROTO_VER_*
    struct TagState state;
    uint8_t         rfu1[1];  // shall be ignored for now
    uint16_t        screenPixWidth;
    uint16_t        screenPixHeight;
    uint16_t        screenMmWidth;
    uint16_t        screenMmHeight;
    uint16_t        compressionsSupported;  // COMPR_TYPE_* bitfield
    uint16_t        maxWaitMsec;            // how long tag will wait for packets before going to sleep
    uint8_t         screenType;             // enum TagScreenType
    uint8_t         rfu[11];                // shall be zero for now
} __attribute__((packed, aligned(1)));

struct AssocInfo {                      // PKT_ASSOC_RESP
    uint32_t checkinDelay;              // space between checkins, in msec
    uint32_t retryDelay;                // if download fails mid-way wait thi smany msec to retry (IFF progress was made)
    uint16_t failedCheckinsTillBlank;   // how many fails till we go blank
    uint16_t failedCheckinsTillDissoc;  // how many fails till we dissociate
    uint32_t newKey[4];
    uint8_t  rfu[8];  // shall be zero for now
} __attribute__((packed, aligned(1)));

#define CHECKIN_TEMP_OFFSET 0x7f

struct CheckinInfo {  // PKT_CHECKIN
    struct TagState state;
    uint8_t         lastPacketLQI;   // zero if not reported/not supported to be reported
    int8_t          lastPacketRSSI;  // zero if not reported/not supported to be reported
    uint8_t         temperature;     // zero if not reported/not supported to be reported. else, this minus CHECKIN_TEMP_OFFSET is temp in degrees C
    uint8_t         rfu[6];          // shall be zero for now
} __attribute__((packed, aligned(1)));

struct PendingInfo {  // PKT_CHECKOUT
    uint64_t imgUpdateVer;
    uint32_t imgUpdateSize;
    uint64_t osUpdateVer;  // version of OS update avail
    uint32_t osUpdateSize;
    uint8_t  rfu[8];  // shall be zero for now
} __attribute__((packed, aligned(1)));

struct ChunkReqInfo {  // PKT_CHUNK_REQ
    uint64_t versionRequested;
    uint32_t offset;
    uint8_t  len;
    uint8_t  osUpdatePlz : 1;
    uint8_t  rfu[6];  // shall be zero for now
} __attribute__((packed, aligned(1)));

struct ChunkInfo {  // PKT_CHUNK_RESP
    uint32_t offset;
    uint8_t  osUpdatePlz : 1;
    uint8_t  rfu;     // shall be zero for now
    uint8_t  data[];  // no data means request is out of bounds of this version no longer exists
} __attribute__((packed, aligned(1)));
