#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#define FIPS202_NAMESPACE(s) pqcrystals_fips202_ref##s

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
} keccak_state;

typedef struct {
	uint64_t s_masked[25 * (KYBER_MASKING_ORDER + 1)];
} keccak_state_masked;

#define shake128_absorb FIPS202_NAMESPACE(_shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(_shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
void shake128_squeezeblocks_masked(uint8_t* out_masked, size_t nblocks, keccak_state_masked* state_masked, size_t outlen);

#define shake256_absorb FIPS202_NAMESPACE(_shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_absorb_masked(keccak_state_masked* state_masked, const uint8_t* in_masked, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(_shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);
void shake256_squeezeblocks_masked(uint8_t* out_masked, size_t nblocks, keccak_state_masked* state_masked, size_t outlen);
#define shake128 FIPS202_NAMESPACE(_shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake128_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);
#define shake256 FIPS202_NAMESPACE(_shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256_masked(uint8_t* out_masked, size_t outlen, const uint8_t* in_masked, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(_sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3_256_masked(uint8_t h_masked[32 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(_sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);
void sha3_512_masked(uint8_t h_masked[64 * (KYBER_MASKING_ORDER + 1)], const uint8_t* in_masked, size_t inlen);

void secMult(uint64_t* c, uint64_t* a, uint64_t* b);
unsigned long rand32bits(void);

void KeccakF1600_StatePermute_masked(uint64_t state_masked[25 * (KYBER_MASKING_ORDER + 1)]);
void KeccakF1600_StatePermute(uint64_t state[25]);
void keccak_absorb_masked(uint64_t s_masked[25 * (KYBER_MASKING_ORDER + 1)],
                          unsigned int r,
                          const uint8_t* m_masked,
                          size_t mlen,
                          uint8_t p);
void keccak_absorb(uint64_t s[25],
                    unsigned int r,
                    const uint8_t* m,
                    size_t mlen,
                    uint8_t p);

void not_mult_xor(uint64_t* r, uint64_t* n, uint64_t* m, uint64_t* x);
#endif
