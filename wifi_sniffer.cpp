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

#include "wifi_sniffer.hpp"

#include <TimeLib.h>

#include "PCAP.h"
#include "WiFi.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "lwip/err.h"
#include "nvs_flash.h"

int sniffed_packet_count = 0;
static PCAP pcap = PCAP();
static unsigned long int last_save = millis();

void cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  /* MISC PKT have 0 bytes payload and should be ignored */
  if (type == WIFI_PKT_MISC)
    return;

  /* Packet too long */
  if (ctrl.sig_len > 2500)
    return;

  uint32_t packetLength = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT)
    packetLength -= 4;  //  fix for known bug in the IDF https://github.com/espressif/esp-idf/issues/886. Thanks to spacehuhn

  uint32_t timestamp = now();                                          // current timestamp
  uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);  // micro seconds offset (0 - 999)

  pcap.newPacketSD(timestamp, microseconds, packetLength, pkt->payload);
  sniffed_packet_count++;
  if (millis() - last_save >= 2000) {
    pcap.flushFile();
    last_save = millis();
  }
}

uint8_t _bssid[6];

static void cb_bssid(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  /* MISC PKT have 0 bytes payload and should be ignored */
  if (type == WIFI_PKT_MISC)
    return;

  /* Packet too long */
  if (ctrl.sig_len > 2500)
    return;

  /* Compare addr1/addr2/addr3 and saved BSSID */
  if (memcmp(&pkt->payload[4], _bssid, 6) != 0 &&
      memcmp(&pkt->payload[10], _bssid, 6) != 0 &&
      memcmp(&pkt->payload[18], _bssid, 6) != 0)
    return;

  uint32_t packetLength = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT)
    packetLength -= 4;  //  fix for known bug in the IDF https://github.com/espressif/esp-idf/issues/886. Thanks to spacehuhn

  uint32_t timestamp = now();                                          // current timestamp
  uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);  // micro seconds offset (0 - 999)

  pcap.newPacketSD(timestamp, microseconds, packetLength, pkt->payload);
  sniffed_packet_count++;
  if (millis() - last_save >= 2000) {
    pcap.flushFile();
    last_save = millis();
  }
}

WifiSniffer::WifiSniffer(const char *filename, FS SD) {
  WiFi.mode(WIFI_AP);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(cb);
  pcap.filename = filename;
  pcap.openFile(SD);
}

WifiSniffer::WifiSniffer(const char *filename, FS SD, int ch) {
  WiFi.mode(WIFI_AP);
  esp_wifi_set_channel(ch, (wifi_second_chan_t)NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(cb_bssid);
  pcap.filename = filename;
  pcap.openFile(SD);
}

WifiSniffer::WifiSniffer(const char *filename, FS SD, uint8_t *bssid, int ch) {
  WiFi.mode(WIFI_AP);
  memcpy(_bssid, bssid, sizeof(uint8_t) * 6);
  esp_wifi_set_channel(ch, (wifi_second_chan_t)NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(cb_bssid);
  pcap.filename = filename;
  pcap.openFile(SD);
}

WifiSniffer::~WifiSniffer() {
  esp_wifi_set_promiscuous(false);
  WiFi.softAPdisconnect(true);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  pcap.closeFile();
  clean_sniffed_packets();
}

int WifiSniffer::get_sniffed_packets() {
  return sniffed_packet_count;
};

void WifiSniffer::clean_sniffed_packets() {
  sniffed_packet_count = 0;
};