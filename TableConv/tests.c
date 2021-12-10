#include "gadgets.h"
#include "random.h"
#include <stdio.h>

#define NB_TESTS 100000

Masked arithm_masking(int a, unsigned q){
  Masked res;
  res.shares[0] = a;
  for(int i=1; i < MASKING_ORDER+1; ++i) res.shares[i] = 0;
  arithmetic_refresh(&res, q);
  return res;
}

Masked bool_masking(int a, unsigned k){
  Masked res;
  res.shares[0] = a;
  for(int i=1; i < MASKING_ORDER+1; ++i) res.shares[i] = 0;
  boolean_refresh(&res, k);
  return res;
}

int arith_unmask(Masked* x, unsigned q){
  int res = 0;
  for(int i=0;i<MASKING_ORDER+1;++i)
    res = (res+x->shares[i])%q;
  return res;
}

int bool_unmask(Masked* x){
  int res = 0;
  for(int i=0;i<MASKING_ORDER+1;++i)
    res = (res^x->shares[i]);
  return res;
}

int test_opt_Z16_to_4bits(){
  unsigned q = 16;
  int val, val2;
  Masked y, x;
  
  for(int i=0; i < NB_TESTS; ++i){
    val = rand32()%q;
    x = arithm_masking(val, q);
    opt_Z16_to_4bits(&x, &y);
    val2 = bool_unmask(&y);

    if (val != val2){
      printf("Val: %i\n", val);
      print_masked_arith(&x, q);
      print_masked_bool(&y);
      return 0;
    }
  }
  printf("Test opt_Z16_to_4bits: success\n");
  return 1;
}

int test_shift1(){
  unsigned k = 13;
  unsigned q = 1<<k;
  int val, val2;
  Masked y, x;
  
  for(int i=0; i < NB_TESTS; ++i){
    val = rand32()%q;
    x = arithm_masking(val, q);
    shift1(&x, &y, k);
    val2 = arith_unmask(&y, q/2);

    if ((val>>1) != val2){
      printf("Test %i failed ! Val: %i Shift: %i\n", i, val, val>>1);
      print_masked_arith(&x, q);
      print_masked_arith(&y, q/2);
      return 0;
    }
  }
  printf("Test shift1: success\n");
  return 1;
}

int test_masked_shift(){
  unsigned k = 13;
  unsigned q = 1<<k;
  int val, val2, l;
  Masked y, x;
  
  for(int i=0; i < NB_TESTS; ++i){
    val = rand32()%q;
    l = (rand32()%(k-2))+1;
    x = arithm_masking(val, q);
    masked_shift(&x, &y, k, l);
    val2 = arith_unmask(&y, q/(1<<l));

    if ((val>>l) != val2){
      printf("Test %i failed ! Val: %i Shift: %i\n", i, val, val>>l);
      print_masked_arith(&x, q);
      print_masked_arith(&y, q/(1<<l));
      return 0;
    }
  }
  printf("Test masked shift: success\n");
  return 1;
}

int test_triple_shift1(){
  unsigned k = 13;
  unsigned q = 1<<k;
  int val, val2, l=3;
  Masked y, x;
  
  for(int i=0; i < NB_TESTS; ++i){
    val = rand32()%q;
    x = arithm_masking(val, q);
    triple_shift1(&x, &y, k);
    val2 = arith_unmask(&y, q/(1<<l));

    if ((val>>l) != val2){
      printf("Test %i failed ! Val: %i Shift: %i\n", i, val, val>>l);
      print_masked_arith(&x, q);
      print_masked_arith(&y, q/(1<<l));
      return 0;
    }
  }
  printf("Test triple shift : success\n");
  return 1;

}

int test_convert_2_l_to_1bit_bool(){  
  Masked y, x;
  unsigned l=8, q=1<<l;
  int val, val2, res;
  for(int i=0; i < (1<<l); ++i){
    val = i;
    res = 0;
    x = arithm_masking(val, q);
    convert_2_l_to_1bit_bool(&x, &y, l);
    val2 = bool_unmask(&y);
    if ((val >= q/4) && (val < 3*q/4)) res = 1;

    if ( res != val2){
      printf("Test %i failed ! Val: %i bit:%i\n", i, val, val2);
      print_masked_arith(&x, q);
      print_masked_bool(&y);
      return 0;
    }  
  }
  printf("Test convert 2^l to 1 bit: success\n");
  return 1;
}

int test_convert_B2A(){

  unsigned k = 13;
  unsigned q = 1 << k;
  int val, val2;
  Masked y, x;
  
  for(int i=0; i < NB_TESTS; ++i){
    val = rand32()%q;
    x = bool_masking(val, k);
    convert_B2A(&x, &y, k, q);
    val2 = arith_unmask(&y, q);

    if (val != val2){
      printf("Test %i failed ! Val: %i Converted val: %i\n", i, val, val2);
      print_masked_bool(&x);
      print_masked_arith(&y, q);
      return 0;
    }
  }
  printf("Test convert B2A : success\n");
  return 1;

}

int test_optimized_convert_B2A(){

  unsigned k = 13;
  unsigned q = 1 << k;
  int val, val2;
  Masked y, x;
  
  for(int i=0; i < NB_TESTS; ++i){
    val = rand32()%q;
    x = bool_masking(val, k);
    optimized_convert_B2A(&x, &y, k, q);
    val2 = arith_unmask(&y, q);

    if (val != val2){
      printf("Test %i failed ! Val: %i Converted val: %i\n", i, val, val2);
      print_masked_bool(&x);
      print_masked_arith(&y, q);
      return 0;
    }
  }
  printf("Test optimized convert B2A : success\n");
  return 1;

}


int test_kyber_decryption(){
  unsigned q = 3329;
  int val, val2, res;
  Masked x,y, t;

  unsigned kyber_switch_table[9] = {6, 7, 7, 7, 8, 8, 8, 8, 8};
  unsigned l = kyber_switch_table[MASKING_ORDER-1];

  //delta = 0.02
  for(int i=0; i < NB_TESTS; ++i){ 
    res = 0;
    do{
      val = rand32()%q;
    } while (!(   (val <= 765) 
              || ((val >= 899) && (val <= 2430))
              ||  (val >= 2564))); // Reject if not in R_{q, \delta}

    x = arithm_masking(val, q);
    for(int i=0; i < MASKING_ORDER+1; ++i) t.shares[i] = x.shares[i];
    kyber_decryption(&x, &y);
    val2 = bool_unmask(&y);
    if ((val >= q/4) && (val < 3*q/4)) res = 1;

    if ( res != val2){
      printf("Test %i failed ! Val: %i bit:%i\n", i, val, val2);
      print_masked_arith(&t, q);
      print_masked_arith(&x, 1<<l);
      print_masked_bool(&y);
      return 0;
    }  
  }
  printf("Test Kyber decryption: success\n");
  return 1;
}

void tests(){
  test_opt_Z16_to_4bits();
  test_shift1();
  test_masked_shift();
  test_triple_shift1();
  test_convert_2_l_to_1bit_bool();
  test_optimized_convert_B2A();
  test_kyber_decryption();
}