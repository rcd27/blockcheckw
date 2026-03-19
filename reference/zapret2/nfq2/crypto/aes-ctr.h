#pragma once

#include <stdint.h>
#include "aes.h"

void aes_ctr_xcrypt_buffer(aes_context *ctx, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out);
int aes_ctr_crypt(const uint8_t *key, unsigned int key_len, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out);
void ctr_add(uint8_t *counter, uint64_t add);
