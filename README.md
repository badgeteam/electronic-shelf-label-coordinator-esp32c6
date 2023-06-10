Shelf Label Coordinator
=====

This application is designed to work with electronic shelf labels flashed with
the atc1441 or firmware with a compatible protocol. More information on that 
[here](https://github.com/atc1441/ZBS_Flasher). Refer to that link and the 
subsequent links for a list of compatible hardware.

Implemented functionality
* Respond to protocol events and associate a device
* Upload hardcoded image per request of the tag
* Optionally provide debug logging on protocol and radio events

Supported hardware
---

This project needs an ESP32 with an onboard 802.15.4 radio. Like the ESP32H2 or 
the ESP32C6. The application in the current version is verified to work on the 
ESP32-C6-DevKitC-1 with Solumn shelf labels of type ST-QR29000 flashed with firmware 
1.9.0.0 .

Building
----

This is a regular [esp-idf](https://github.com/espressif/esp-idf) project. Follow their 
instructions to build the project.

TL;DR
```text
. ${IDF_PATH}/export.sh

idf.py -p <device> build flash monitor
```
