#include "aes-ctr.h"
#include <string.h>

#define AES_BLOCKLEN 16


// add 64-bit value to 16-byte big endian counter
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
void ctr_add(uint8_t *counter, uint64_t add)
{
#ifndef __BYTE_ORDER__
 #error "__BYTE_ORDER__ not defined"
#endif
	uint64_t *c = (uint64_t*)counter;

#if __BYTE_ORDER__==__ORDER_BIG_ENDIAN__
	uint64_t sum = c[1] + add;
	if (sum < c[1]) // overflow
		c[0]++;
	c[1] = sum;
#else
	uint64_t lsw = __builtin_bswap64(c[1]);
	uint64_t sum = lsw + add;
	if (sum < lsw) // overflow
		c[0] = __builtin_bswap64(__builtin_bswap64(c[0]) + 1);
	c[1] = __builtin_bswap64(sum);
#endif
}

// increment 16-byte big endian counter
static inline void ctr_increment(uint8_t *counter)
{
	for (int8_t bi = (AES_BLOCKLEN - 1); (bi >= 0) && !++counter[bi]; bi--);
}

#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize ("no-strict-aliasing")))
#endif
void aes_ctr_xcrypt_buffer(aes_context *ctx, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out)
{
	uint8_t bi, ivc[AES_BLOCKLEN], buffer[AES_BLOCKLEN];
	size_t i, l16 = length & ~0xF;

	memcpy(ivc, iv, AES_BLOCKLEN);

	for (i = 0; i < l16; i += 16)
	{
		aes_cipher(ctx, ivc, buffer);
		ctr_increment(ivc);
		*((uint64_t*)(out + i)) = *((uint64_t*)(in + i)) ^ ((uint64_t*)buffer)[0];
		*((uint64_t*)(out + i + 8)) = *((uint64_t*)(in + i + 8)) ^ ((uint64_t*)buffer)[1];
	}

	if (i<length)
	{
		memcpy(buffer, ivc, AES_BLOCKLEN);
		aes_cipher(ctx, buffer, buffer);

		for (bi=0 ; i < length; i++, bi++)
			out[i] = in[i] ^ buffer[bi];
	}
}

int aes_ctr_crypt(const uint8_t *key, unsigned int key_len, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out)
{
	int ret = 0;
	aes_context ctx;

	aes_init_keygen_tables();

	if (!(ret = aes_setkey(&ctx, AES_ENCRYPT, key, key_len)))
		aes_ctr_xcrypt_buffer(&ctx, iv, in, length, out);

	return ret;
}
