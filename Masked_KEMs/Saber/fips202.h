#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>
#include "SABER_params.h"
#include "gadgets.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
} keccak_state;

typedef struct {
	uint64_t s_masked[25 * (MASKING_ORDER + 1)];
} keccak_state_masked;


void shake128(unsigned char *output, unsigned long long outlen, const unsigned char *input, unsigned long long inlen);
void sha3_256(unsigned char *output, const unsigned char *input, unsigned long long inlen);
void sha3_512(unsigned char *output, const unsigned char *input, unsigned long long inlen);


void shake128_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen);
void shake256_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen);


void shake128_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);
void shake256_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);

void sha3_256_masked(uint8_t h_masked[32 * (MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);
void sha3_512_masked(uint8_t h_masked[64 * (MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);

void secMult(uint64_t* c, uint64_t* a, uint64_t* b);

void KeccakF1600_StatePermute_masked(uint64_t state_masked[25 * (MASKING_ORDER + 1)]);
//void KeccakF1600_StatePermute(uint64_t state[25]);
void keccak_absorb_masked(uint64_t s_masked[25 * (MASKING_ORDER + 1)],
                          unsigned int r,
                          const uint8_t* m_masked,
                          size_t mlen,
                          uint8_t p);
/*void keccak_absorb(uint64_t s[25],
                    unsigned int r,
                    const uint8_t* m,
                    size_t mlen,
                    uint8_t p);*/
#endif
