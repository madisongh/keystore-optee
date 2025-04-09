#ifndef user_ta_header_defines___h
#define user_ta_header_defines___h

#include "keystore.h"

#define TA_UUID KEYSTORE_TA_UUID

#define TA_FLAGS (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_INSTANCE_KEEP_ALIVE | TA_FLAG_DEVICE_ENUM_SUPP)
#define TA_STACK_SIZE (2 * 1024)
#define TA_DATA_SIZE (32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
  { "gp.ta.description", USER_TA_PROP_TYPE_STRING, "Secure storage for keys/passphrases" }, \
  { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t) { 0x0011 } }

#endif /* user_ta_header_defines__h */
