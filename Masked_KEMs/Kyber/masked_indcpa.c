#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "rng.h"
#include "ntt.h"
#include "symmetric.h"
#include "gadgets.h"
#include "debug.h"

#include <string.h>

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)
/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:             pointer to output public-key
*                                         polynomial vector
*              - uint8_t *seed:           pointer to output seed to generate
*                                         matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec* pk,
    uint8_t seed[KYBER_SYMBYTES],
    const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
    size_t i;
    polyvec_frombytes(pk, packedpk);
    for (i = 0; i < KYBER_SYMBYTES; i++)
        seed[i] = packedpk[i + KYBER_POLYVECBYTES];
}


/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk:   pointer to the input vector of polynomials b
*              poly *v:    pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES],
                            polyvec* b,
                            poly* v)
{
    polyvec_compress(r, b);
    poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}
/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:             pointer to output vector of
*                                         polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
/*static void unpack_masked_sk(masked_polyvec* sk,
                             const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES*(KYBER_MASKING_ORDER+1)])
{
    polyvec_masked_frombytes(sk, packedsk);
}*/
/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c:           pointer to output ciphertext
*                                      (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m:     pointer to input message
*                                      (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk:    pointer to input public key
*                                      (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins
*                                      used as seed (of length KYBER_SYMBYTES)
*                                      to deterministically generate all
*                                      randomness
**************************************************/
void indcpa_masked_enc(uint8_t masked_c[KYBER_INDCPA_BYTES * (KYBER_MASKING_ORDER + 1)],
                       const uint8_t masked_m[KYBER_INDCPA_MSGBYTES * (KYBER_MASKING_ORDER + 1)],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec pkpv, at[KYBER_K];
  masked_poly masked_v, masked_k, masked_epp;
  masked_polyvec masked_sp, masked_ep, masked_bp;
  polyvec bp;
  poly v;
  unpack_pk(&pkpv, seed, pk);
  poly_masked_frommsg(&masked_k, masked_m);
  gen_at(at, seed); //Public key generation
  
  for (i = 0; i < KYBER_K; i++)
  {
      masked_poly_getnoise_eta1(&(masked_sp.vec_shares[i]), masked_coins, nonce++);
  }


  for (i = 0; i < KYBER_K; i++)
  {
      masked_poly_getnoise_eta2(&(masked_ep.vec_shares[i]), masked_coins, nonce++);
      
  }
  masked_poly_getnoise_eta2(&masked_epp, masked_coins, nonce++); 


  polyvec_masked_ntt(&masked_sp);

  

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_halfmasked_pointwise_acc_montgomery(&masked_bp.vec_shares[i], &at[i], &masked_sp);


  

  polyvec_halfmasked_pointwise_acc_montgomery(&masked_v, &pkpv, &masked_sp);



  polyvec_masked_invntt_tomont(&masked_bp);
  poly_masked_invntt_tomont(&masked_v);


  polyvec_masked_add(&masked_bp, &masked_bp, &masked_ep);
  poly_masked_add(&masked_v, &masked_v, &masked_epp);
  poly_masked_add(&masked_v, &masked_v, &masked_k);
  polyvec_masked_reduce(&masked_bp);
  poly_masked_reduce(&masked_v);
  



  unmask_poly(&masked_v, &v);

  //Only for testing, useless in the future
  //memcpy(&v, &(masked_v.poly_shares[0]), KYBER_N * 2);
  for (i = 0; i < (KYBER_K); i++)
  {
      unmask_poly(&(masked_bp.vec_shares[i]), &bp.vec[i]);
      //memcpy(&(bp.vec[i]) , &(masked_bp.vec_shares[i].poly_shares[0]), KYBER_N * 2);

  } 


  
  pack_ciphertext(masked_c, &bp, &v); // TODO
}


void indcpa_masked_enc_no_compress(Masked ct[KYBER_N*(KYBER_K+1)],
                       const uint8_t masked_m[KYBER_INDCPA_MSGBYTES * (KYBER_MASKING_ORDER + 1)],
                       const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       const uint8_t masked_coins[KYBER_SYMBYTES * (KYBER_MASKING_ORDER + 1)])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec pkpv, at[KYBER_K];
  masked_poly masked_v, masked_k, masked_epp;
  masked_polyvec masked_sp, masked_ep, masked_bp;
  unpack_pk(&pkpv, seed, pk);
  poly_masked_frommsg(&masked_k, masked_m);
  gen_at(at, seed); //Public key generation
  
  for (i = 0; i < KYBER_K; i++)
  {
      masked_poly_getnoise_eta1(&(masked_sp.vec_shares[i]), masked_coins, nonce++);
  }


  for (i = 0; i < KYBER_K; i++)
  {
      masked_poly_getnoise_eta2(&(masked_ep.vec_shares[i]), masked_coins, nonce++);
      
  }
  masked_poly_getnoise_eta2(&masked_epp, masked_coins, nonce++); 


  polyvec_masked_ntt(&masked_sp);

  

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_halfmasked_pointwise_acc_montgomery(&masked_bp.vec_shares[i], &at[i], &masked_sp);


  

  polyvec_halfmasked_pointwise_acc_montgomery(&masked_v, &pkpv, &masked_sp);



  polyvec_masked_invntt_tomont(&masked_bp);
  poly_masked_invntt_tomont(&masked_v);


  polyvec_masked_add(&masked_bp, &masked_bp, &masked_ep);
  poly_masked_add(&masked_v, &masked_v, &masked_epp);
  poly_masked_add(&masked_v, &masked_v, &masked_k);
  polyvec_masked_reduce(&masked_bp);
  poly_masked_reduce(&masked_v);
  

  for(i=0; i < KYBER_K; ++i){
    for(int j=0; j < KYBER_N; ++j){
      for(int k=0; k < KYBER_MASKING_ORDER+1; ++k){
        ct[i*KYBER_N + j].shares[k] = (((masked_bp).vec_shares[i]).poly_shares[k]).coeffs[j]; 
      }
    }
  }

  for(int j=0; j < KYBER_N; ++j){
    for(int k=0; k < KYBER_MASKING_ORDER+1; ++k){
      ct[KYBER_K*KYBER_N + j].shares[k] = (masked_v.poly_shares[k]).coeffs[j]; 
    }
  }
}


/*************************************************
* Name:        indcpa_masked_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m:        pointer to output decrypted message
*                                   (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c:  pointer to input ciphertext
*                                   (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_masked_dec(uint8_t m[KYBER_INDCPA_MSGBYTES*(KYBER_MASKING_ORDER+1)],
                       const uint8_t c[KYBER_INDCPA_BYTES],
                       const masked_polyvec* skpv)
{
  masked_poly mp;
  polyvec bp;
  poly v;

  unpack_ciphertext(&bp, &v, c);

  polyvec_ntt(&bp);
  polyvec_halfmasked_pointwise_acc_montgomery(&mp, &bp, skpv);
  poly_masked_invntt_tomont(&mp);

  poly_halfmasked_sub(&mp, &v, &mp);
  poly_masked_reduce(&mp);

  poly_masked_tomsg(m, &mp);
}