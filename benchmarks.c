#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include "gadgets.h"
#include "cpucycles.h"
#include "random.h"
#include "convba_2014.h"

#ifndef ITER
#define ITER 10000
#endif

#ifdef COUNT
uint64_t count_rand = 0;
#endif

uint64_t start, stop;


/* Benchmarks our paper */

void benchmark_opt_Z16_to_4bits(){
  Masked y, x;
  start = cpucycles();
  for(int i=0; i < ITER; i++) opt_Z16_to_4bits(&x, &y);
  stop = cpucycles();
  printf("Avg speed opt_Z16_to_4bits: %f cycles.\n", (double)(stop-start)/ITER);
}


void benchmark_shift1(){
  unsigned k=13;
  Masked y, x;
  start = cpucycles();
  for(int i=0; i < ITER; i++) shift1(&x, &y, k);
  stop = cpucycles();
  printf("Avg speed shift1: %f cycles.\n", (double)(stop-start)/ITER);
}

void benchmark_triple_shift1(){
  unsigned k=13;
  Masked y, x;
  start = cpucycles();
  for(int i=0; i < ITER; i++) triple_shift1(&x, &y, k);
  stop = cpucycles();
  printf("Avg speed triple shift: %f cycles.\n", (double)(stop-start)/ITER);
}



void benchmark_convert_2_l_to_1bit_bool(){
  unsigned l=8;
  Masked y, x;
  start = cpucycles();
  for(int i=0; i < ITER; i++) convert_2_l_to_1bit_bool(&x, &y, l);
  stop = cpucycles();
  printf("Avg speed convert 2^l to 1bit bool: %f cycles.\n", (double)(stop-start)/ITER);
}


void benchmark_kyber_decrypt(){
  Masked y, x;
  start = cpucycles();
  for(int i=0; i < ITER; i++) kyber_decryption(&x, &y);
  stop = cpucycles();
  printf("Avg speed kyber decrypt: %f cycles.\n", (double)(stop-start)/ITER);
}


void benchmark_convert_1bit_B2A(){
  unsigned q=3329;
  Masked y, x;
  start = cpucycles();
  for(int i=0; i < ITER; i++) optimized_convert_B2A(&x, &y, 1, q);
  stop = cpucycles();
  printf("Avg speed convert 1 bit B2A: %f cycles.\n", (double)(stop-start)/ITER);
}  


/* Benchmarks others */
void benchmark_CGV14_Z16_to_4bits(){
   uint32_t y[MASKING_ORDER+1], x[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) ConvertAB(x,y,4,MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed CGV14 Z16_to_4bits: %f cycles.\n", (double)(stop-start)/ITER);
}

void benchmark_CGV14_shift1(){
  unsigned k=13;
  uint32_t y[MASKING_ORDER+1], x[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) shift(x, y, k, 1, MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed CGV14 shift1: %f cycles.\n", (double)(stop-start)/ITER);
}


void benchmark_CGV14_triple_shift(){
  unsigned k=13;
  uint32_t y[MASKING_ORDER+1], x[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) shift(x, y, k, 3, MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed CGV14 triple shift: %f cycles.\n", (double)(stop-start)/ITER);
}


void benchmark_CGV14_convert_2_l_to_1bit_bool(){
  unsigned l=5;
  uint32_t x[MASKING_ORDER+1], b[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) thresholdmod2k(x,b,l,MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed CGV14 convert 2^l to 1bit bool: %f cycles.\n", (double)(stop-start)/ITER);
}

void benchmark_CGV14_saber_decrypt(){
  uint32_t x[MASKING_ORDER+1], b[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) saberdecrypt(x,b,MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed CGV14 saberdecrypt: %f cycles.\n", (double)(stop-start)/ITER);
}

void benchmark_BBE18_kyber_decrypt(){
  uint32_t x[MASKING_ORDER+1], b[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) kyberdecrypt(x,b,MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed BBE18 kyberdecrypt: %f cycles.\n", (double)(stop-start)/ITER);
}


void benchmark_SPOG_convert_1bit_B2A(){
  unsigned q=3329;
  uint32_t x[MASKING_ORDER+1], y[MASKING_ORDER+1];
  start = cpucycles();
  for(int i=0; i < ITER; i++) ConvertBA_SPOG(x, y, q, MASKING_ORDER+1);
  stop = cpucycles();
  printf("Avg speed SPOG convert 1 bit B2A: %f cycles.\n", (double)(stop-start)/ITER);
} 


void random_counting(){
#ifdef COUNT

  unsigned k = 13, l = 5, q = 3329;
  Masked y, x;

  count_rand = 0;
  opt_Z16_to_4bits(&x, &y);
  printf("Random usage opt_Z16_to_4bits: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  shift1(&x, &y, k);
  printf("Random usage shift1: : %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  triple_shift1(&x, &y, k);
  printf("Random usage triple shift1: : %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  convert_2_l_to_1bit_bool(&x, &y, l, 0);
  printf("Random usage 2^l to 1bit bool: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  optimized_convert_B2A(&x, &y, 1, q);
  printf("Random usage convert 1 bit B2A: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  saber_decryption(&x, &y);
  printf("Random usage Saber decryption: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  kyber_decryption(&x, &y);
  printf("Random usage Kyber decryption: %lu uint_32t.\n\n\n", count_rand);


  /* Old gadgets */

  uint32_t y2[MASKING_ORDER+1], x2[MASKING_ORDER+1];

  count_rand = 0;
  ConvertAB(x2,y2,4,MASKING_ORDER+1);
  printf("Random usage CGV14 Z16_to_4bits: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  shift(x2, y2, k, 1, MASKING_ORDER+1);
  printf("Random usage CGV14 shift1: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  shift(x2, y2, k, 3, MASKING_ORDER+1);
  printf("Random usage CGV14 triple shift1: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  thresholdmod2k(x2, y2,l,MASKING_ORDER+1);
  printf("Random usage CGV14 convert 2^l to 1bit bool: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  ConvertBA_SPOG(x2, y2, MASKING_ORDER+1);
  printf("Random usage SPOG convert 1 bit B2A: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  saberdecrypt(x2,y2,MASKING_ORDER+1);
  printf("Random usage CGV14 Saber decrypt: %lu uint_32t.\n\n\n", count_rand);

  count_rand = 0;
  kyberdecrypt(x2,y2,MASKING_ORDER+1);
  printf("Random usage BBE18 Kyber decrypt: %lu uint_32t.\n\n\n", count_rand);


#else
  printf("COUNT mode not enabled\n");
#endif
}


int main(){
  printf("Number of shares: %i, rng mode: %i\n", MASKING_ORDER+1, RNG_MODE);

  #ifdef COUNT
  random_counting();
  #else

  
  printf("Our paper: \n");
  benchmark_opt_Z16_to_4bits();
  benchmark_shift1();
  benchmark_triple_shift1();
  benchmark_convert_1bit_B2A();
  benchmark_kyber_decrypt();

  
  printf("\n\nPrevious work: \n");
  benchmark_CGV14_Z16_to_4bits();
  benchmark_CGV14_shift1();
  benchmark_CGV14_triple_shift();
  benchmark_SPOG_convert_1bit_B2A();
  benchmark_CGV14_saber_decrypt();
  benchmark_BBE18_kyber_decrypt();

  printf("\n");
  #endif
  
  return 0;
}
