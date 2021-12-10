#include "debug.h"
#define DISPLAY_SIZE 20


void print_poly(poly* p){
  for(int i=0; i < DISPLAY_SIZE; ++i){
    printf("%i ", p->coeffs[i]); 
  }
  printf("\n");
}


void unmask_poly(masked_poly* mp, poly* p){
  int16_t temp;
  for(int i=0; i < KYBER_N; ++i){
    temp = 0;
    for(int j=0; j < KYBER_MASKING_ORDER+1; ++j){
      temp = (temp + (mp->poly_shares[j].coeffs[i]))%KYBER_Q;
    }
    p->coeffs[i]=temp;
  }
}


void compare_poly(poly* a, poly* b){
  for(int i=0; i < KYBER_N; ++i){
    if ((a->coeffs[i]+KYBER_Q)%KYBER_Q != (b->coeffs[i]+KYBER_Q)%KYBER_Q){
      printf("NOK... Position: %i, val1: %i, val2: %i\n",i, a->coeffs[i],b->coeffs[i]);
      return;
    }
  }
  printf("OK\n");
}


void print_masked_poly(masked_poly* mp){
  poly p;
  unmask_poly(mp,&p);
  print_poly(&p);
}


void print_masked_polyvec(masked_polyvec* mpv){
  printf("Masked Polyvec:\n");
  for(int i=0; i < KYBER_K; ++i){
    printf("Masked Poly %i :", i);
    print_masked_poly(&(mpv->vec_shares[i]));
  }
}


void print_polyvec(polyvec* pv){
  printf("Polyvec:\n");
  for(int i=0; i < KYBER_K; ++i){
    printf("Poly %i :", i);
    print_poly(&(pv->vec[i]));
  }
}