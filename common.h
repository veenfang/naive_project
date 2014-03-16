#ifndef _X_COMMON_
#define _X_COMMON_

#define LOGBUFFER_SIZE 128

#define ieee80211mhz2chan(x) \
        (((x) <= 2484) ? \
        (((x) == 2484) ? 14 : ((x) - 2407) / 5) : \
        ((x) / 5) - 1000)

#endif
