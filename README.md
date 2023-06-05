Shelf Label Coordinator
===

Example output
---
```text
I (98692) 802.15.4 radio: rx OK, received 66 bytes
I (98702) 802.15.4 radio: Frame type:                   1
I (98712) 802.15.4 radio: Security Enabled:             False
I (98722) 802.15.4 radio: Frame pending:                False
I (98722) 802.15.4 radio: Acknowledge request:          False
I (98732) 802.15.4 radio: PAN ID Compression:           False
I (98742) 802.15.4 radio: Reserved:                     False
I (98742) 802.15.4 radio: Sequence Number Suppression:  False
I (98752) 802.15.4 radio: Information Elements Present: False
I (98762) 802.15.4 radio: Destination addressing mode:  2
I (98762) 802.15.4 radio: Frame version:                0
I (98772) 802.15.4 radio: Source addressing mode:       3
E (98772) 802.15.4 radio: PAN identifier not compressed, ignoring packet
I (98782) 802.15.4 radio: Data (0)
I (98792) 802.15.4 radio: Broadcast on PAN 4447
I (98792) 802.15.4 radio: Originating from long address 02:83:92:02:3b:19:ff:ff
I (98802) 802.15.4 radio: Data length: 47
I (98802) 802.15.4 radio: Checksum: 0adb
I (98812) 802.15.4 radio: PAN 4447 S 0000 02:83:92:02:3B:19:FF:FF to ffff 00:00:00:00:00:00:00:00 BROADCAST
D (98822) gdma: new group (0) at 0x4087ebbc
D (98822) gdma: new pair (0,0) at 0x4087ebf0
D (98832) gdma: new tx channel (0,0) at 0x4087eb88
D (98832) gdma: new rx channel (0,0) at 0x4087ec10
D (98842) gdma: tx channel (0,0), (1:0) bytes aligned, burst enabled
D (98842) gdma: rx channel (0,0), (1:0) bytes aligned, burst disabled
[02:83:92:02:3B:19:FF:FF] to [FF:FF:FF:FF:FF:FF:FF:FF]: Assoc request  proto v0, sw v1181116006400, hw 0008, batt 2600 mV, w 128 px (29 mm), h 296 px (67 mm), c 0002, maxWait 200 ms, screenType 16
```

```text
E (130958) 802.15.4 radio: PAN identifier not compressed, ignoring packet
I (130958) 802.15.4 radio: Data (1)
I (130968) 802.15.4 radio: Broadcast on PAN 4447
I (130968) 802.15.4 radio: Originating from long address 02:bd:08:3f:3b:19:ff:ff
I (130978) 802.15.4 radio: Data length: 47
I (130988) 802.15.4 radio: Checksum: 0bcd
I (130988) 802.15.4 radio: PAN 4447 S 0000 02:BD:08:3F:3B:19:FF:FF to ffff 00:00:00:00:00:00:00:00 BROADCAST
I (130998) 802.15.4 radio: Nonce:
I (130998) 802.15.4 radio: 01 00 00 00 ff ff 19 3b 3f 08 bd 02 00
I (131008) 802.15.4 radio: Tag:
I (131018) 802.15.4 radio: 0f 6e 50 e9
I (131018) 802.15.4 radio: Encrypted:
I (131018) 802.15.4 radio: 0x4080e512   05 62 63 7b 11 3b b7 a7  89 f9 a7 1e a1 48 40 80  |.bc{.;.......H@.|
I (131038) 802.15.4 radio: 0x4080e522   ae 66 55 65 62 39 87 d7  41 1d dd 5f 77 a2 bd 47  |.fUeb9..A.._w..G|
I (131048) 802.15.4 radio: 0x4080e532   6c 1e 70 c2 dc e2 87 0f  6e 50 e9 01 00 00 00     |l.p.....nP.....|
I (131058) 802.15.4 radio: Plain:
I (131058) 802.15.4 radio: 0x408130e0   f0 00 00 00 00 00 13 01  00 00 08 00 28 0a 00 80  |............(...|
I (131068) 802.15.4 radio: 0x408130f0   00 28 01 1d 00 43 00 02  00 c8 00 10 00 00 00 00  |.(...C..........|
I (131078) 802.15.4 radio: 0x40813100   00 00 00 00 00 00 00                              |.......|
[02:BD:08:3F:3B:19:FF:FF] to [FF:FF:FF:FF:FF:FF:FF:FF]: Assoc request  proto v0, sw v1181116006400, hw 0008, batt 2600 mV, w 128 px (29 mm), h 296 px (67 mm), c 0002, maxWait 200 ms, screenType 16
```