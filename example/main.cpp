/*
 * This file is part of the Capibara zero project(https://capibarazero.github.io/).
 * Copyright (c) 2023 Andrea Canale.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <Arduino.h>
#include "SD.h"
#include "SPI.h"
#include "wifi_sniffer.hpp"

bool file_exists = false;
#define CHANGE_CHANNEL_TIME 5000  // Switch channel every 5 seconds
#define PCAP_FILE "/example_capture.pcap"

// SPI pins for ESP32-S3
#define SCK 13
#define MISO 12
#define MOSI 11
#define SS 10
#define MAX_WIFI_CHANNEL 13 // Max channel that ESP32 will use for scanning

void setup()
{
    /* Only if you use ESP32-S3 or have issues with SPI */
    SPI.begin(SCK, MISO, MOSI, SS);

    if (!SD.begin(SS))
    {
        printf("Failed to initialize SD card\n");
    }
    else
    {
        printf("Intialized SD card\n");
    };

    /* Create PCAP file */
    File fptr = SD.open(PCAP_FILE, FILE_WRITE);
    fptr.close();

    file_exists = SD.exists(PCAP_FILE);
}

WifiSniffer sniffer = WifiSniffer(PCAP_FILE, SD);

void loop()
{

    if (file_exists)
    {
        // Change channel
        for (int i = 1; i < MAX_WIFI_CHANNEL; i++)
        {
            esp_wifi_set_channel(i, (wifi_second_chan_t)NULL);
            delay(CHANGE_CHANNEL_TIME); // Wait before changing channel, sniffer will sniff meanwhile.
        }
    }
}