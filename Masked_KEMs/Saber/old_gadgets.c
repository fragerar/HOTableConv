#include <stdint.h>
#include "gadgets.h"
#include "random.h"


void sec_mult(Masked* a, Masked* b, Masked* c, unsigned q){
  uint16_t r, t;
  for(int i=0; i < MASKING_ORDER+1; ++i) c->shares[i] = (a->shares[i]*b->shares[i])%q;

  for(int i=0; i < MASKING_ORDER+1; ++i){

    for(int j=i+1; j < MASKING_ORDER+1; ++j){
      r = rand16()%q;
      t = ((r+a->shares[i]*b->shares[j])+a->shares[j]*b->shares[i])%q;
      c->shares[i] = (c->shares[i] + q - r)%q;
      c->shares[j] = (c->shares[j] + t)%q;
    }
  }
}


void sec_and(Masked* x, Masked* y, Masked* res, int k){

#if MASKING_ORDER == 1
    uint16_t u = rand16()&((1<<k)-1);
    uint16_t z;
    z = u ^ (x->shares[0] & y->shares[0]);
    z = z ^ (x->shares[0] & y->shares[1]);
    z = z ^ (x->shares[1] & y->shares[0]);
    z = z ^ (x->shares[1] & y->shares[1]);
    res->shares[0] = z;
    res->shares[1] = u;

#else
    Masked r;
    uint16_t i, j, z_ij, z_ji;
    for(i=0; i < MASKING_ORDER + 1; ++i) r.shares[i] = x->shares[i] & y->shares[i];
    for(i=0; i < MASKING_ORDER + 1; ++i)
        for(j=i+1; j < MASKING_ORDER + 1; ++j){
            z_ij  = rand16()&((1<<k)-1);
            z_ji  = (x->shares[i] & y->shares[j]) ^ z_ij;
            z_ji ^= (x->shares[j] & y->shares[i]);
            r.shares[i] ^= z_ij;
            r.shares[j] ^= z_ji;            
        }
    for(i=0; i < MASKING_ORDER + 1; ++i) res->shares[i] = r.shares[i];
#endif

}


void arithmetic_refresh(Masked* x, unsigned q){
  int r;
  for(int i=0; i < MASKING_ORDER+1; ++i){
    for(int j=i+1; j < MASKING_ORDER+1; ++j){
      r = (int) rand32()%q;     
      x->shares[i] = (x->shares[i] + r)%q;
      x->shares[j] = (x->shares[j] - r + q)%q;
    }
  }
}


void boolean_refresh(Masked* x, unsigned k){
  int r;
  for(int i=0; i< MASKING_ORDER+1; ++i){
    for(int j=i+1; j < MASKING_ORDER+1; ++j){
      r = (int) rand32() & ((1<<k)-1);
      x->shares[i] = (x->shares[i] ^ r);
      x->shares[j] = (x->shares[j] ^ r);
    }
  }
}


void linear_arithmetic_refresh(Masked* x, unsigned q){
  int r;
  for(int i=0; i< MASKING_ORDER; ++i){

    r = (int) rand32()%q;     
    x->shares[i] = (x->shares[i] + r)%q;
    x->shares[MASKING_ORDER] = (x->shares[MASKING_ORDER] - r + q)%q;
  }
}


void linear_boolean_refresh(Masked* x, unsigned k){
  int r;
  for(int i=0; i< MASKING_ORDER; ++i){
    r = (int) rand32() & ((1<<k)-1);
    x->shares[i] = (x->shares[i] ^ r);
    x->shares[MASKING_ORDER] = (x->shares[MASKING_ORDER] ^ r);
  }
}


static void refresh_masks_n(uint16_t* x, uint16_t* y, const int N){
	uint16_t r;
	y[N-1] = x[N-1];
	for(int i=0; i <  N-1; ++i){
		r = rand16();
		y[i] = x[i] ^ r;
		y[N-1] = y[N-1] ^ r;
	}
}


void goubin_bool_arith(uint16_t* bool_x, uint16_t* arith_x){
	/*
	 *
	 * http://www.goubin.fr/papers/arith-final.pdf
	 */

	uint16_t g = rand16();
	uint16_t t = bool_x[0] ^ g;
	t = t - g;
	t = t ^ bool_x[0];
	g = g ^ bool_x[1];
	arith_x[0] = bool_x[0] ^ g;
	arith_x[0] = arith_x[0] - g;
	arith_x[0] = arith_x[0] ^ t;
	arith_x[1] = bool_x[1];
	
}


static void HO_bool_arith(uint16_t* bool_x, uint16_t* arith_x, const int N){
	/*
	 * High order boolean to arithmetic masking conversion of value x
	 * INPUT: boolean masking of x, number of shares N
	 * OUTPUT: arithmetic masking of x
	 * See 2017/252
	 */

	if (N==2)	{
		goubin_bool_arith(bool_x, arith_x);
		return;
	}	
	uint16_t x[N+1], a[N+1], b[N], c[N], d[N], e[N-1], f[N-1], A[N-1], B[N-1];

	for(int i=0; i < N; ++i) x[i] = bool_x[i];
	x[N] = 0;
	refresh_masks_n(x, a, N+1);
	b[0] = ((~N & 1)*a[0]) ^ ((a[0] ^ a[1]) - a[1]); 
	for(int i=1; i < N; ++i)
		b[i] = (a[0] ^ a[i+1]) - a[i+1];
	
	refresh_masks_n(a+1, c, N);
	refresh_masks_n(b,   d, N);

	for(int i = 0; i < N-2; ++i) e[i] = c[i];
	for(int i = 0; i < N-2; ++i) f[i] = d[i];


	e[N-2] = c[N-2] ^ c[N-1];
	f[N-2] = d[N-2] ^ d[N-1];

	HO_bool_arith(e, A, N-1);
	HO_bool_arith(f, B, N-1);

	for(int i = 0; i < N-2; ++i) arith_x[i] = A[i] + B[i];
	arith_x[N-2] = A[N-2];
	arith_x[N-1] = B[N-2];

}


void exponential_B2A(Masked* x, Masked *y){
  HO_bool_arith(x->shares, y->shares, MASKING_ORDER+1);
}

/*

  Debug functions

*/

void print_masked_arith(Masked* x, int q){
  printf(" (");
  int t=0;
  for(int i=0; i < MASKING_ORDER; ++i){
    printf("%u, ",x->shares[i]);
    t += x->shares[i];
  }
  t += x->shares[MASKING_ORDER];
  printf("%u) = %u = %u mod %u\n", x->shares[MASKING_ORDER], t, t%q, q);

}

void print_masked_arith_poly(Masked x[SABER_N], int q){
  for(int i = 0; i < SABER_N; ++i)
    print_masked_arith(&(x[i]), q);
  printf("\n\n\n");
}
 

void print_masked_bool(Masked* y){
  int t=0;
  printf(" (");
  for(int i=0; i < MASKING_ORDER; ++i){
    printf("%u, ",y->shares[i]);
    t ^= y->shares[i];
  }
  t ^= y->shares[MASKING_ORDER];
  printf("%i) = (", y->shares[MASKING_ORDER]);
  for(int i=0; i < MASKING_ORDER; ++i){
    printf("0x%X, ", y->shares[i]);
  }
  printf("0x%x) = %u\n", y->shares[MASKING_ORDER], t);
}

void print_masked_bool_poly(Masked x[SABER_N]){
  for(int i = 0; i < SABER_N; ++i)
    print_masked_bool(&(x[i]));
  printf("\n\n\n");
}

void unmask_bitstring(uint8_t* bs, int size){
  uint8_t unmasked_buf[size];

  for(int i=0; i < size; ++i) unmasked_buf[i] = 0;
  for(int k=0; k < MASKING_ORDER+1; ++k){
    for(int i=0; i < size; ++i) unmasked_buf[i] ^= bs[i+k*size];
  }
  for(int i=0; i < size; ++i) printf("%X ",unmasked_buf[i]);
  printf("\n");
}