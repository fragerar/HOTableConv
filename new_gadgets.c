#include "gadgets.h"
#include <stdint.h>
#include "random.h"


static uint64_t right_rot64(uint64_t val, unsigned rot, unsigned size){
  return (uint64_t)(val >> (size*rot)) + (uint64_t)(val<<(64-size*rot));
}

void opt_Z16_to_4bits(Masked* x, Masked* y){
  /* 
   * Arithmetic to Boolean conversion from Z_{16} to {0,1}^4 
   */ 

  #if MASKING_ORDER == 1
  uint64_t t1 = 0xFEDCBA9876543210LLU, t2 = 0;
  t1 = right_rot64(t1, x->shares[0], 4);
  t2 = rand64();
  t1 ^= t2;
  y->shares[0] = (t1>>(4*x->shares[1]))&(0xF);
  y->shares[1] = (t2>>(4*x->shares[1]))&(0xF);
  boolean_refresh(y, 4);
  #else

  uint64_t table_columns[MASKING_ORDER+1];
  uint64_t r;
  table_columns[0] = 0xFEDCBA9876543210LLU;
  for(int i=1; i < MASKING_ORDER+1; ++i) table_columns[i] = 0;

  for(int i=0; i < MASKING_ORDER; ++i){
    for(int j=0; j < MASKING_ORDER+1; ++j){
      table_columns[j] = right_rot64(table_columns[j], x->shares[i], 4);
    }
    
    for(int j=0; j < MASKING_ORDER; ++j){
      r = (uint64_t)rand64();
      table_columns[j] ^= r;
      table_columns[MASKING_ORDER] ^= r;
    }
  }
  for(int i=0; i < MASKING_ORDER+1; ++i) y->shares[i] = (table_columns[i]>>(4*x->shares[MASKING_ORDER]))&(0xF); 
  boolean_refresh(y, 4);



  #endif
}


void shift1(Masked* z, Masked* a, unsigned k){
  /* 
   * Arithmetic to Arithmetic shift of 1 position from Z_{k} to Z_{k-1}
   */



  // Commented section below this line is the generic code
  /*
  Masked x, c;
  Masked T[2*(MASKING_ORDER+1)];
  
  for(int i=0; i < MASKING_ORDER+1; ++i) x.shares[i] = z->shares[i]&1;
  for(int u=0; u < 2*(MASKING_ORDER+1); ++u) {
    T[u].shares[0] = u >> 1;
    for(int i=1; i < MASKING_ORDER+1; ++i) T[u].shares[i] = 0;
  }
  for(int i=0; i < MASKING_ORDER; ++i){
    for(int u=0; u < 2*((MASKING_ORDER+1)-(i+1)); ++u){
      for(int j=0; j < MASKING_ORDER+1; ++j) T[u].shares[j] = T[u+x.shares[i]].shares[j];
      arithmetic_refresh(&(T[u]), 1<<(k-1));
    }
  }
  for(int i=0; i < MASKING_ORDER+1; ++i) c.shares[i] = T[x.shares[MASKING_ORDER]].shares[i];
  arithmetic_refresh(&c, 1<<(k-1));
  for(int i=0; i < MASKING_ORDER+1; ++i) a->shares[i] = ((z->shares[i] >> 1) + c.shares[i])%(1<<(k-1));
  */
 

  #if MASKING_ORDER == 1

  Masked x, c_bool, c;
  char T[2]; 
  char r;
  
  for(int i=0; i < MASKING_ORDER+1; ++i) x.shares[i] = z->shares[i]&1;
  T[0]  = 0xC >> (x.shares[0]); 
  T[1]  = rand32();
  T[0] ^= T[1];
  c_bool.shares[0] = (T[0]>>(x.shares[1]))&1;
  c_bool.shares[1] = (T[1]>>(x.shares[1]))&1;
  r = rand32();
  c_bool.shares[0] = (c_bool.shares[0]^r)&1;
  c_bool.shares[1] = (c_bool.shares[1]^r)&1;
    
  exponential_B2A(&c_bool, &c); // Fast conversion for small orders

  for(int i=0; i < MASKING_ORDER+1; ++i) a->shares[i] = ((z->shares[i] >> 1) + (c.shares[i]&((1<<(k-1))-1)))%(1<<(k-1));
  #elif MASKING_ORDER < 7

  Masked x, c_bool, c;
  uint16_t T[MASKING_ORDER+1];
  uint16_t r;

  for(int i=0; i < MASKING_ORDER+1; ++i) x.shares[i] = z->shares[i]&1;
  T[0] = 0xFA50;
  for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0;



  for(int i=0; i < MASKING_ORDER; ++i){
    for(int j=0; j < MASKING_ORDER+1; ++j) T[j]>>= (2*x.shares[i]);
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand16();
      T[j] ^= r;
      T[MASKING_ORDER] ^= r;
    }
  }

  for(int i=0; i < MASKING_ORDER+1; ++i) c_bool.shares[i] = (T[i]>>(2*x.shares[MASKING_ORDER]))&3; 
  for(int j=0; j < MASKING_ORDER; ++j){
    r = rand16();
    c_bool.shares[j] ^= r;
    c_bool.shares[MASKING_ORDER] ^= r;
  }

  optimized_convert_B2A(&c_bool, &c, 2, 1<<(k-1));
  for(int i=0; i < MASKING_ORDER+1; ++i) a->shares[i] = ((z->shares[i] >> 1) + (c.shares[i]&((1<<(k-1))-1)))%(1<<(k-1));


  #elif MASKING_ORDER < 15
  Masked x, c_bool, c;
  uint64_t T[MASKING_ORDER+1];
  uint64_t r;

  for(int i=0; i < MASKING_ORDER+1; ++i) x.shares[i] = z->shares[i]&1;
  T[0] = 0x9988FF6B646D2240;
  for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0;



  for(int i=0; i < MASKING_ORDER; ++i){
    for(int j=0; j < MASKING_ORDER+1; ++j) T[j]>>= (3*x.shares[i]);
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand64();
      T[j] ^= r;
      T[MASKING_ORDER] ^= r;
    }
  }

  for(int i=0; i < MASKING_ORDER+1; ++i) c_bool.shares[i] = (T[i]>>(3*x.shares[MASKING_ORDER]))&7; 
  for(int j=0; j < MASKING_ORDER; ++j){
    r = rand64();
    c_bool.shares[j] ^= r;
    c_bool.shares[MASKING_ORDER] ^= r;
  }

  optimized_convert_B2A(&c_bool, &c, 3, 1<<(k-1));
  for(int i=0; i < MASKING_ORDER+1; ++i) a->shares[i] = ((z->shares[i] >> 1) + (c.shares[i]&((1<<(k-1))-1)))%(1<<(k-1));
  #endif
}

void masked_shift(Masked* x, Masked* y, unsigned k, unsigned l){
  /*
   * Performs an arbitrary masked shift by iterating the shift of one position
   */
  for(int i=0; i < l; ++i){
    shift1(x, y, k-i);
    x=y;
  }
}

void triple_shift1(Masked* z, Masked* a, unsigned k){
  /*
   * Arithmetic to Arithmetic shift of 3 positions from Z_{k} to Z_{k-3}
   */

  #if MASKING_ORDER > 3
  /* If we have more than 4 shares, we iterate three times
     the shift of one position to avoid large tables */
  masked_shift(z, a, k, 3);
  #elif MASKING_ORDER == 1

  Masked x, c_bool, c;
  int16_t T[2];
  int16_t r;

  for(int i=0; i < MASKING_ORDER+1; ++i) x.shares[i] = z->shares[i]&7;
  T[0]  = 0xFF00 >> (x.shares[0]); 
  T[1]  = rand16();
  T[0] ^= T[1];
  c_bool.shares[0] = (T[0]>>(x.shares[1]))&1;
  c_bool.shares[1] = (T[1]>>(x.shares[1]))&1;
  r = rand16();
  c_bool.shares[0] = (c_bool.shares[0]^r)&1;
  c_bool.shares[1] = (c_bool.shares[1]^r)&1;
    
  exponential_B2A(&c_bool, &c);

  for(int i=0; i < MASKING_ORDER+1; ++i) a->shares[i] = ((z->shares[i] >> 3) + (c.shares[i]&((1<<(k-3))-1)))%(1<<(k-3));

  #elif MASKING_ORDER < 4


  Masked x, c_bool, c;
  uint64_t T[MASKING_ORDER+1];
  uint64_t r;

  for(int i=0; i < MASKING_ORDER+1; ++i) x.shares[i] = z->shares[i]&7;
  T[0] = 0xFFFFAAAA55550000LLU;
  for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0LLU;

  
  for(int i=0; i < MASKING_ORDER; ++i){
    for(int j=0; j < MASKING_ORDER+1; ++j) T[j]>>= (2*x.shares[i]);
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand64();
      T[j] ^= r;
      T[MASKING_ORDER] ^= r;
    }
  }
  for(int i=0; i < MASKING_ORDER+1; ++i) c_bool.shares[i] = (T[i]>>(2*x.shares[MASKING_ORDER]))&3; 
  for(int j=0; j < MASKING_ORDER; ++j){
    r = rand64();
    c_bool.shares[j] ^= r;
    c_bool.shares[MASKING_ORDER] ^= r;
  }
  //exponential_B2A(&c_bool, &c);
  optimized_convert_B2A(&c_bool, &c, 2, 1<<(k-3));
  for(int i=0; i < MASKING_ORDER+1; ++i) a->shares[i] = ((z->shares[i] >> 3) + (c.shares[i]&((1<<(k-3))-1)))%(1<<(k-3));

  #endif

}


void modulus_switch(Masked* x, unsigned q, unsigned shift){
  /* 
   * Modulus switch between Z_q and Z_{2^shift} 
   * round((x<<shift)/q) = ((x<<(shift+1) + q1)//(2*q)
   * No overflow should appear for the values we use in the paper
   */
  int64_t temp;
  for(int i =0; i < MASKING_ORDER+1; ++i) {
    temp = (int64_t)(x->shares[i]) << (shift+1);
    temp = (temp+q)/(2*q);
    x->shares[i] = (int)temp&((1<<shift)-1);
  }

}


unsigned switch_table[9] =  {6, 7, 7, 7, 8, 8, 8, 8, 8}; // Value of \ell in the paper

void kyber_decryption(Masked* x, Masked* b){
  unsigned l = switch_table[MASKING_ORDER-1];
  modulus_switch(x, 3329, l);
  convert_2_l_to_1bit_bool(x, b, l);
}


void convert_2_l_to_1bit_bool(Masked* x, Masked* b, unsigned l){
  /* 
    Arithmetic to Boolean conversion from 2^\ell to 1 bit
    using a threshold function. 
  */


  if (l == 4){
    uint16_t T[MASKING_ORDER+1];
    uint16_t r;
    T[0] = 0x0FF0;


    for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0;
    
    for(int i=0; i < MASKING_ORDER; ++i){
      for(int j=0; j < MASKING_ORDER+1; ++j) T[j] = (T[j] << (16-x->shares[i])) + (T[j]>>(x->shares[i]));
      for(int j=0; j < MASKING_ORDER; ++j){
        r = rand16();
        T[j] ^= r;
        T[MASKING_ORDER] ^= r;
      }
    }
    for(int i=0; i < MASKING_ORDER+1; ++i) b->shares[i] = (T[i]>>(x->shares[MASKING_ORDER]))&1; 
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand16();
      b->shares[j] ^= r;
      b->shares[MASKING_ORDER] ^= r;
    }
  }
  else if (l == 5){
    uint32_t T[MASKING_ORDER+1];
    uint32_t r;


    T[0] = 0x00FFFF00;

    for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0;
    
    for(int i=0; i < MASKING_ORDER; ++i){
      for(int j=0; j < MASKING_ORDER+1; ++j) T[j] = (T[j] << (32-x->shares[i])) + (T[j]>>(x->shares[i]));
      for(int j=0; j < MASKING_ORDER; ++j){
        r = rand32();
        T[j] ^= r;
        T[MASKING_ORDER] ^= r;
      }
    }
    for(int i=0; i < MASKING_ORDER+1; ++i) b->shares[i] = (T[i]>>(x->shares[MASKING_ORDER]))&1; 
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand32();
      b->shares[j] ^= r;
      b->shares[MASKING_ORDER] ^= r;
    }
  }

  else if (l == 6){
    uint64_t T[MASKING_ORDER+1];
    uint64_t r;

    T[0] = 0x0000FFFFFFFF0000LLU;

    for(int i=1; i < MASKING_ORDER+1; ++i) T[i] = 0;
    
    for(int i=0; i < MASKING_ORDER; ++i){
      for(int j=0; j < MASKING_ORDER+1; ++j) T[j] = (T[j] << (64-x->shares[i])) + (T[j]>>(x->shares[i]));
      for(int j=0; j < MASKING_ORDER; ++j){
        r = rand64();
        T[j] ^= r;
        T[MASKING_ORDER] ^= r;
      }
    }
    for(int i=0; i < MASKING_ORDER+1; ++i) b->shares[i] = (T[i]>>(x->shares[MASKING_ORDER]))&1; 
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand64();
      b->shares[j] ^= r;
      b->shares[MASKING_ORDER] ^= r;
    }
  }

  else if (l == 7){
    uint64_t T1[MASKING_ORDER+1];
    uint64_t T2[MASKING_ORDER+1];
    uint64_t r;
    unsigned shift;

  

    T1[0] = 0xFFFFFFFF00000000LLU;
    T2[0] = 0x00000000FFFFFFFFLLU;
 

    for(int i=1; i < MASKING_ORDER+1; ++i) {
      T1[i] = 0;
      T2[i] = 0;
    }
    
    for(int i=0; i < MASKING_ORDER; ++i){
      for(int j=0; j < MASKING_ORDER+1; ++j){
        shift = x->shares[i];
        if (shift%64 != 0){
          r = T1[j];
          T1[j] = (T1[j] >> (shift%64)) + (T2[j] << (64-(shift%64)));
          T2[j] = (T2[j] >> (shift%64)) + (r << (64-(shift%64)));
        }
        if (shift >= 64){
          r = T2[j];
          T2[j] = T1[j];
          T1[j] = r;
         }
      }
      for(int j=0; j < MASKING_ORDER; ++j){
        r = rand64();
        T1[j] ^= r;
        T1[MASKING_ORDER] ^= r;
        r = rand64();
        T2[j] ^= r;
        T2[MASKING_ORDER] ^= r;
      }
    }
    

    
    for(int i=0; i < MASKING_ORDER+1; ++i){
      shift = x->shares[MASKING_ORDER];
      if (shift < 64) b->shares[i] = (T1[i]>>(shift))&1;
      else            b->shares[i] = (T2[i]>>(shift-64))&1;
    }
    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand32();
      b->shares[j] ^= r;
      b->shares[MASKING_ORDER] ^= r;
    }

  }

  else if (l == 8){

    uint64_t T[4][MASKING_ORDER+1];
    uint64_t T_p[4][MASKING_ORDER+1];
    uint64_t r;
    unsigned shift, jump, small_shift;

  

    T[0][0] = 0x0000000000000000LLU;
    T[1][0] = 0xFFFFFFFFFFFFFFFFLLU;
    T[2][0] = 0xFFFFFFFFFFFFFFFFLLU;
    T[3][0] = 0x0000000000000000LLU;

    for(int i=1; i < MASKING_ORDER+1; ++i) {
      T[0][i] = 0;
      T[1][i] = 0;
      T[2][i] = 0;
      T[3][i] = 0;
    }
    
    for(int i=0; i < MASKING_ORDER; ++i){
      for(int j=0; j < MASKING_ORDER+1; ++j){
        shift = x->shares[i];
        jump = shift/64;
        small_shift = shift%64;

        for(int k=0; k < 4; ++k)
          T_p[(k-jump+4)%4][j] = T[k][j];
        for(int k=0; k < 4; ++k){
          if(small_shift != 0) 
            T[k][j] = (T_p[k][j] >> small_shift) | (T_p[(k+1)%4][j] << (64-small_shift));
          else
            T[k][j] = T_p[k][j];
        }
        
      }
      for(int j=0; j < MASKING_ORDER; ++j){
        r = rand64();
        T[0][j] ^= r;
        T[0][MASKING_ORDER] ^= r;
        r = rand64();
        T[1][j] ^= r;
        T[1][MASKING_ORDER] ^= r;
        r = rand64();
        T[2][j] ^= r;
        T[2][MASKING_ORDER] ^= r;
        r = rand64();
        T[3][j] ^= r;
        T[3][MASKING_ORDER] ^= r;

      }
    }
    
    for(int i=0; i < MASKING_ORDER+1; ++i){
      shift = x->shares[MASKING_ORDER];
      b->shares[i] = (T[shift/64][i] >> (shift%64))&1;
    }

    for(int j=0; j < MASKING_ORDER; ++j){
      r = rand32();
      b->shares[j] ^= r;
      b->shares[MASKING_ORDER] ^= r;
    }

  }

} 

void convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q){
  /*
   * Generic Boolean to arithmetic conversion from G={0,1}^k to H=Z_{q} 
   */
  Masked T[(1<<k)];
  Masked T_p[(1<<k)];
  
  for(int u=0; u < (1<<k); ++u){
    T[u].shares[0] = u%q;
    for(int i=1; i < MASKING_ORDER+1; ++i) T[u].shares[i] = 0;
  }
  for(int i=0; i < MASKING_ORDER; ++i){
    for(int u=0; u < (1<<k); ++u){
      for(int j=0; j < MASKING_ORDER+1; ++j){
        T_p[u].shares[j] = T[u^(x->shares[i])].shares[j]; 
      }
    }
    for(int u=0; u < (1<<k); ++u){
      arithmetic_refresh(&(T_p[u]), q); 
      for(int i=0; i < MASKING_ORDER+1; ++i) T[u].shares[i] = T_p[u].shares[i];
    }
  }
  for(int i=0; i < MASKING_ORDER+1; ++i) y->shares[i] = T[x->shares[MASKING_ORDER]].shares[i]; 
  arithmetic_refresh(y, q);


}

void optimized_convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q){ 
  /*
   * Optimized Boolean to arithmetic conversion from G={0,1}^k to H=Z_{q}  
   * using a small size 1 generic convert
   */
  Masked z, t; 
  for(int i=0; i < MASKING_ORDER+1; ++i) y->shares[i] = 0;

  for(int j=0; j < k; ++j){
    for(int i=0; i < MASKING_ORDER+1; ++i) z.shares[i] = (x->shares[i] >> j)&1;
    convert_B2A(&z, &t, 1, q);
    for(int i=0; i < MASKING_ORDER+1; ++i) y->shares[i] = (y->shares[i] + (t.shares[i]<<j))%q;
  }

}