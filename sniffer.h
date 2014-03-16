#ifndef ___SNIFFER_H___
#define ___SNIFFER_H___

#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include "common.h"

struct pkg_util_info{
  uint64_t Tsft;
  uint8_t Flag;
  uint8_t Rate;
  uint8_t Channel;
  uint8_t Fhss;
  int Antenna_signal;
  int Antenna_noise;
  uint16_t Lock_quality;
  uint16_t Tx_attenuation;
  uint16_t Db_tx_attenuation;
  int Dbm_tx_power;
  uint8_t Antenna;
  uint8_t Db_antenna_signal;
  uint8_t Db_antenna_noise;
};

#endif
