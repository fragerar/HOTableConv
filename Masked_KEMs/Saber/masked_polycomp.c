#include <stdio.h>
#include "random.h"
#include "gadgets.h"
#include "SABER_params.h"

#define NTESTS 100

void boolean_zero_test(Masked* x, Masked* y, int k, int logk){
  Masked z;
  y->shares[0] = (~x->shares[0]) | ((1<<(1<<logk))-(1<<k));
  for(int i=1; i < MASKING_ORDER+1; ++i) y->shares[i] = x->shares[i];

  for(int i=0; i < logk; ++i){
    for(int j=0; j < MASKING_ORDER+1; ++j) z.shares[j] = y->shares[j] >> (1 << i);
    boolean_refresh(&z, k);
    sec_and(y, &z, y, k); 
  }
  for(int i=0; i < MASKING_ORDER+1; ++i) y->shares[i] = (y->shares[i])&1;

  boolean_refresh(y, k);
}


void bool_poly_zero_test(Masked* poly, Masked* b, int k, int logk, const unsigned SIZE){
  Masked temp1, temp2;
  Masked *p1=&temp1, *p2=&temp2, *swap;
  temp1.shares[0] = 0xFFFF; 
  for(int i=1; i < MASKING_ORDER+1; ++i) temp1.shares[i] = 0;

  for(int i=0; i < SIZE; ++i){
    poly[i].shares[0] = ~poly[i].shares[0]; 
    sec_and(&(poly[i]), p1, p2, k);
    swap = p2;
    p2 = p1;
    p1 = swap;
  }
  temp1.shares[0] = ~temp1.shares[0];

  boolean_zero_test(&temp1, b, k, logk);

}


int saber_ct_zero_test_boolean(Masked* masked_poly){
  Masked b1;
  int res = 0;
  unsigned l1=768, l2=256;  
  bool_poly_zero_test(masked_poly, &b1, 10, 4, l1+l2);
  boolean_refresh(&b1, 16);
  for(int i=0; i < MASKING_ORDER+1; ++i) res ^= b1.shares[i]; 
  return res;
}
 













static uint32_t genrand(int l)
{
  if (l==32) return rand32();
  return rand32() & ((1 << l)-1);
}

static void refreshBool(uint32_t a[],int l,int n)
{
  for(int i=0;i<n-1;i++)
  {
    uint32_t tmp=genrand(l);
    a[n-1]=a[n-1] ^ tmp;
    a[i]=a[i] ^ tmp;
  }
}


static void SecAnd(uint32_t *a,uint32_t *b,uint32_t *c,int k,int n)
{
  for(int i=0;i<n;i++)
    c[i]=a[i] & b[i];

  for(int i=0;i<n;i++)
  {
    for(int j=i+1;j<n;j++)
    {
      uint32_t tmp=rand32(); 
      uint32_t tmp2=(tmp ^ (a[i] & b[j])) ^ (a[j] & b[i]);
      c[i]^=tmp;
      c[j]^=tmp2;
    }
  }
  for(int i=0;i<n;i++) c[i]=c[i] % (1 << k);
}

static void SecAdd(uint32_t *x,uint32_t *y,uint32_t *z,int k,int n)
{
  uint32_t u[n];
  for(int i=0;i<n;i++) u[i]=0;
  uint32_t w[n];
  SecAnd(x,y,w,k,n);
  uint32_t a[n];
  for(int i=0;i<n;i++) a[i]=x[i] ^ y[i];
  for(int j=0;j<k-1;j++)
  {
    uint32_t ua[n];
    SecAnd(u,a,ua,k,n);
    for(int i=0;i<n;i++) u[i]=(2*(ua[i] ^ w[i])) % (1 << k);
  }
  for(int i=0;i<n;i++) z[i]=x[i] ^ y[i] ^ u[i];
}



static void Expand(uint32_t *x,uint32_t *xp,int k,int n2,int n)
{
  for(int i=0;i<n/2;i++)
  {
    uint32_t r=genrand(k);
    xp[2*i]=x[i] ^ r;
    xp[2*i+1]=r;
  }
  if ((n & 1)==1) 
  {
    if (n2==n/2)
      xp[n-1]=0;
    else
      xp[n-1]=x[n2-1];
  }
}

// Goubin's first order conversion from arithmetic to Boolean
// Returns x such that A+r=x xor r
static uint32_t GoubinAB(uint32_t A,uint32_t r,int k)
{
  uint32_t G=rand32();
  uint32_t T=G << 1;
  uint32_t x=G ^ r;
  uint32_t O=G & x;
  x=T ^ A;
  G=G ^ x;
  G=G & r;
  O=O ^ G;
  G=T & A;
  O=O ^ G;
  for(int i=1;i<k;i++)
  {
    G=T & r;
    G=G ^ O;
    T=T & A;
    G=G ^ T;
    T=G << 1;
  }
  x=x ^ T;
  return x;
}



    
static void ConvertAB(uint32_t *A,uint32_t *z,int k,int n)
{
  if(n==1)
  {
    z[0]=A[0];
    return;
  }

  if(n==2)
  {
    z[0]=GoubinAB(A[0],A[1],k);
    z[1]=A[1];
    return;
  }

  uint32_t x[n/2];
  ConvertAB(A,x,k,n/2);
  uint32_t xp[n];
  Expand(x,xp,k,n/2,n);
  
  uint32_t y[(n+1)/2];
  ConvertAB(A+n/2,y,k,(n+1)/2);
  uint32_t yp[n];
  Expand(y,yp,k,(n+1)/2,n);

  SecAdd(xp,yp,z,k,n);
}


static uint32_t xorop(uint32_t a[],int n)
{
  uint32_t r=0;
  for(int i=0;i<n;i++)
    r^=a[i];
  return r;
}

static void ConvertBA(uint32_t *x,uint32_t *A,int k,int n)
{
  for(int i=0;i<n-1;i++) A[i]=genrand(k);
  uint32_t Ap[n];
  for(int i=0;i<n-1;i++) Ap[i]=-A[i];
  Ap[n-1]=0;

  uint32_t y[n];
  ConvertAB(Ap,y,k,n);

  uint32_t z[n];
  SecAdd(x,y,z,k,n);
  
  for(int i=0;i<n;i++)
    refreshBool(z,k,n);

  A[n-1]=xorop(z,n);
}

void convert_A2B_CGV14(Masked* x, Masked* y, unsigned k1, unsigned k2){

  uint32_t t1[MASKING_ORDER+1], t2[MASKING_ORDER+1];
  for(int i=0; i < MASKING_ORDER+1; ++i) t1[i] = (uint32_t)x->shares[i];
  ConvertAB(t1, t2, k1, MASKING_ORDER+1);  
  for(int i=0; i < MASKING_ORDER+1; ++i)  y->shares[i]= (uint16_t)t2[i]%(1<<k2);

}

void convert_B2A_CGV14(Masked* x, Masked* y, unsigned k){

  uint32_t t1[MASKING_ORDER+1], t2[MASKING_ORDER+1];
  for(int i=0; i < MASKING_ORDER+1; ++i) t1[i] = (uint32_t)x->shares[i];
  ConvertBA(t1, t2, k, MASKING_ORDER+1);  
  for(int i=0; i < MASKING_ORDER+1; ++i)  y->shares[i]= (uint16_t)t2[i]%(1<<k);

}


