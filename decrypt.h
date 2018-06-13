#ifndef _DECRYPT_H
#define _DECRYPT_H

#include "keepcrack.h"

void decrypt_database();
int generate_composite_key(const char *passwd, int pw_len, unsigned char *composite_key);
int generate_master_key(unsigned char *mkey, const unsigned char *tnsfrm_key, struct header_values_t hv);
int verify_decrypt(const unsigned char *streamstartbytes, const unsigned char *dec_payload, uint16_t len);

#endif
