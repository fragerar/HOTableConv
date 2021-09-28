#include <stdint.h>
#include "gadgets.h"
#include "random.h"

void arithmetic_refresh(Masked* x, unsigned q){
  int r;
  for(int i=0; i< MASKING_ORDER; ++i){
    /*
      If q is not a power of two, the following sampling is not uniform.
      We keep it like that for simplicity but rejection sampling should
      be used for secure code.
     */
    r = (int) rand32()%q;     
    x->shares[i] = (x->shares[i] + r)%q;
    x->shares[MASKING_ORDER] = (x->shares[MASKING_ORDER] - r + q)%q;
  }
}



void boolean_refresh(Masked* x, unsigned k){
  int r;
  for(int i=0; i< MASKING_ORDER; ++i){
    r = (int) rand32() & ((1<<k)-1);
    x->shares[i] = (x->shares[i] ^ r);
    x->shares[MASKING_ORDER] = (x->shares[MASKING_ORDER] ^ r);
  }
}

void refresh_masks_n(int* x, int* y, const int N){
	/*
	 * Variable size refresh of masks
	 *
	 */

	int r;
	y[N-1] = x[N-1];
	for(int i=0; i <  N-1; ++i){
		r = rand32();
		y[i] = x[i] ^ r;
		y[N-1] = y[N-1] ^ r;
	}
}

void goubin_bool_arith(int* bool_x, int* arith_x){
	/*
	 *
	 * http://www.goubin.fr/papers/arith-final.pdf
	 */

	int g = rand32();
	int t = bool_x[0] ^ g;
	t = t - g;
	t = t ^ bool_x[0];
	g = g ^ bool_x[1];
	arith_x[0] = bool_x[0] ^ g;
	arith_x[0] = arith_x[0] - g;
	arith_x[0] = arith_x[0] ^ t;
	arith_x[1] = bool_x[1];
	
}


void HO_bool_arith(int* bool_x, int* arith_x, const int N){
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
	int x[N+1], a[N+1], b[N], c[N], d[N], e[N-1], f[N-1], A[N-1], B[N-1];

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
    printf("%i, ",x->shares[i]);
    t += x->shares[i];
  }
  t += x->shares[MASKING_ORDER];
  printf("%i) = %i = %i mod %u\n", x->shares[MASKING_ORDER], t, t%q, q);

}
 

void print_masked_bool(Masked* y){
  int t=0;
  printf(" (");
  for(int i=0; i < MASKING_ORDER; ++i){
    printf("%i, ",y->shares[i]);
    t ^= y->shares[i];
  }
  t ^= y->shares[MASKING_ORDER];
  printf("%i) = (", y->shares[MASKING_ORDER]);
  for(int i=0; i < MASKING_ORDER; ++i){
    printf("0x%X, ", y->shares[i]);
  }
  printf("0x%x) = %i\n", y->shares[MASKING_ORDER], t);
}
