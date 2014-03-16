#include "sniffer.h"
#include "radiotap-parser.h"
#include "ieee80211_radiotap.h"

void rd_init(struct pkg_util_info *rd)
{
  rd->Tsft=0;
  rd->Flag=0;
  rd->Rate=0;
  rd->Channel=0;
  rd->Fhss=0;
  rd->Antenna_signal=0;
  rd->Antenna_noise=0;
  rd->Lock_quality=0;
  rd->Tx_attenuation=0;
  rd->Db_tx_attenuation=0;
  rd->Dbm_tx_power=0;
  rd->Antenna=0;
  rd->Db_antenna_signal=0;
  rd->Db_antenna_noise=0;
}

uint16_t radiotap_get(struct pkg_util_info *rd,const u_char *packet,uint32_t len)
{
  struct ieee80211_radiotap_header *radiotap;
  struct ieee80211_radiotap_iterator iterator;
  
  radiotap=(struct ieee80211_radiotap_header *)packet;

  if (radiotap->it_version>PKTHDR_RADIOTAP_VERSION){
    return 0;
  }
  
  if (radiotap->it_len<8 || radiotap->it_len>len){
    return 0;
  }
  
  ieee80211_radiotap_iterator_init(&iterator,radiotap,radiotap->it_len);
  
  while (ieee80211_radiotap_iterator_next(&iterator)>=0){
    switch (iterator.this_arg_index){    
      case IEEE80211_RADIOTAP_TSFT:
        rd->Tsft=(uint64_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_FLAGS:
        rd->Flag=(uint8_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_RATE:
        rd->Rate=(uint8_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_CHANNEL: 
        rd->Channel=(uint8_t)ieee80211mhz2chan((uint32_t)((iterator.this_arg[1])*256+(iterator.this_arg[0]))) | 0x80;
        break;
      case IEEE80211_RADIOTAP_FHSS:
        rd->Fhss=(uint8_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        rd->Antenna_signal=(uint8_t)*iterator.this_arg-256;
        break;
      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        rd->Antenna_noise=(uint8_t)*iterator.this_arg-256;
        break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:
        rd->Lock_quality=(uint16_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_TX_ATTENUATION:
        rd->Tx_attenuation=(uint16_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        rd->Db_tx_attenuation=(uint16_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_DBM_TX_POWER:
        rd->Dbm_tx_power=(int)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_ANTENNA:
        rd->Antenna=(uint8_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        rd->Db_antenna_signal=(uint8_t)*iterator.this_arg;
        break;
      case IEEE80211_RADIOTAP_DB_ANTNOISE:
        rd->Db_antenna_noise=(uint8_t)*iterator.this_arg;
        break;
    }      	 
  }
  return radiotap->it_len;
}

