// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License version 2 as published
// by the Free Software Foundation.

// The file contains:
// 1) Arithmetic to Boolean conversion modulo 2^k from [CGV14]
// 2) Boolean to arithmetic conversion modulo 2^k from [CGV14]
// 3) Arithmetic to Boolean conversion modulo p, using the extended approach from [BBE+18]
// 4) Boolean to arithmetic conversion modulo p, using the extended approach from [BBE+18]
// 5) Boolean to arithmetic conversion modulo p from [SPOG19]

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include "random.h"



#ifdef TEST
static uint32_t x=123456789, y=362436069, z=521288629;
#endif

uint32_t xorshf96(void) {  
  #ifdef TEST
  
  uint32_t t;

  x ^= x << 16;
  x ^= x >> 5;
  x ^= x << 1;

  t = x;
  x = y;
  y = z;
  z = t ^ x ^ y; 
  return z;
  
  #endif // TEST
  
  return rand32();
  //return rand()&(0xFFFFFFFF);
}

uint32_t genrand(int l)
{
  if (l==32) return xorshf96();
  return xorshf96() & ((1 << l)-1);
}

void share(uint32_t x,uint32_t a[],int n)
{
  int i;
  a[0]=x;
  for(i=1;i<n;i++)
    a[i]=0;
}

void refreshBool(uint32_t a[],int l,int n)
{
  for(int i=0;i<n-1;i++)
  {
    uint32_t tmp=genrand(l);
    a[n-1]=a[n-1] ^ tmp;
    a[i]=a[i] ^ tmp;
  }
}

void FullRefreshBool(uint32_t *a,uint32_t *b,int l,int n)
{
  for(int i=0;i<n;i++) b[i]=a[i];

  for(int i=0;i<n;i++)
    refreshBool(b,l,n);
}

void refreshArith(uint32_t a[],int l,int n)
{
  //int i;
  uint32_t ma=(1 << l)-1; 
  for(int i=0;i<n-1;i++)
  {
    uint32_t tmp=xorshf96();
    a[n-1]=(a[n-1] + tmp) & ma;
    a[i]=(a[i] - tmp) & ma;
  }
}

uint32_t xorop(uint32_t a[],int n)
{
  int i;
  uint32_t r=0;
  for(i=0;i<n;i++)
    r^=a[i];
  return r;
}

uint32_t addop(uint32_t a[],int l,int n)
{
  uint32_t r=0;
  for(int i=0;i<n;i++)
    r+=a[i];
  if (l==32)
    return r;
  else
    return r % (1 << l);
}

uint32_t addopmodp(uint32_t *a,int p,int n)
{
  uint32_t r=0;
  for(int i=0;i<n;i++)
    r+=a[i];
  return r % p;
}


void printShares(uint32_t *a,int n)
{
  for(int i=0;i<n;i++)
    printf("%u ",a[i]);
  printf("\n");
}

void initTab(uint32_t *a,int n)
{
  for(int i=0;i<n;i++)
    a[i]=0;
}

int incTab(uint32_t *a,int l,int n)
{
  int lim=1 << l;
  for(int i=0;i<n;i++)
  {
    a[i]+=1;
    if(a[i]<lim) break;
    a[i]=0;
    if(i==(n-1)) return 1;
  }
  return 0;
}

uint32_t AddGoubin(uint32_t x,uint32_t y,int k)
{
  uint32_t u=0;
  uint32_t w= x & y;
  uint32_t a= x ^ y;
  for(int i=0;i<k-1;i++)
    u=2*( (u & a) ^ w);
  return a ^ u;
}

// We must have p<2^31
uint32_t AddGoubinModp(uint32_t x,uint32_t y,int k,uint32_t p)
{
  uint32_t m=-1;
  uint32_t s=AddGoubin(x,y,k);
  uint32_t sp=AddGoubin(s,-p,k);
  uint32_t b=-(sp >> (k-1));
  return (s & b) ^ (sp & (m ^ b)); 
}

void SecAnd(uint32_t *a,uint32_t *b,uint32_t *c,int k,int n)
{
  int i,j; 
  for(i=0;i<n;i++)
    c[i]=a[i] & b[i];

  for(i=0;i<n;i++)
  {
    for(j=i+1;j<n;j++)
    {
      uint32_t tmp=xorshf96(); //rand();
      uint32_t tmp2=(tmp ^ (a[i] & b[j])) ^ (a[j] & b[i]);
      c[i]^=tmp;
      c[j]^=tmp2;
    }
  }
  for(i=0;i<n;i++) c[i]=c[i] % (1 << k);
}

void SecAdd(uint32_t *x,uint32_t *y,uint32_t *z,int k,int n)
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

void testSecAdd()
{
  int n=3,l=3;
  int l2=1 << l;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    initTab(b,n);
    while (1)
    {
      uint32_t c[n];
      SecAdd(a,b,c,l,n);
      assert(((xorop(a,n)+xorop(b,n)) % l2)==xorop(c,n) % l2);
      if(incTab(b,l,n)) break;
    }
    if(incTab(a,l,n)) break;
  }
}

void SecMul(uint32_t *a,uint32_t *b,uint32_t *c,int p,int n)
{
  int i,j; 
  for(i=0;i<n;i++)
    c[i]=(a[i]*b[i]) % p;

  for(i=0;i<n;i++)
  {
    for(j=i+1;j<n;j++)
    {
      uint32_t tmp=xorshf96() % p; //rand();
      uint32_t tmp2=((tmp+a[i]*b[j])+a[j]*b[i]) % p;
      c[i]=(c[i]+p-tmp) % p;
      c[j]=(c[j]+tmp2) % p;
    }
  }
}

void testSecMul()
{
  int p=3329;
  int n=3,l=3;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    initTab(b,n);
    while (1)
    {
      uint32_t c[n];
      SecMul(a,b,c,p,n);
      assert(((addopmodp(a,p,n)*addopmodp(b,p,n)) % p)==addopmodp(c,p,n));
      if(incTab(b,l,n)) break;
    }
    if(incTab(a,l,n)) break;
  }
}

void ExpandArith(uint32_t *x,uint32_t *xp,int p,int n2,int n)
{
  for(int i=0;i<n/2;i++)
  {
    uint32_t r=xorshf96() % p;
    xp[2*i]=(x[i]+p-r) % p;
    xp[2*i+1]=r % p;
  }
  if ((n & 1)==1) 
  {
    if (n2==n/2)
      xp[n-1]=0;
    else
      xp[n-1]=x[n2-1];
  }
}

void ConvertBA_SPOG(uint32_t *x,uint32_t *y,int p,int n)
{
  if(n==1)
  {
    y[0]=x[0];
    return;
  }

  uint32_t A[n/2];
  ConvertBA_SPOG(x,A,p,n/2);
  uint32_t Ap[n];
  ExpandArith(A,Ap,p,n/2,n);
  
  uint32_t B[(n+1)/2];
  ConvertBA_SPOG(x+n/2,B,p,(n+1)/2);
  uint32_t Bp[n];
  ExpandArith(B,Bp,p,(n+1)/2,n);

  SecMul(Ap,Bp,y,p,n);
  for(int i=0;i<n;i++)
    y[i]=(Ap[i]+Bp[i]-2*y[i]+2*p) % p;
}

void testConvertBA_SPOG()
{
  int p=3329;
  int n=2,l=1;
  uint32_t x[n];
  initTab(x,n);
  while (1)
  {
    uint32_t A[n];
    ConvertBA_SPOG(x,A,p,n);
    assert((xorop(x,n)==addopmodp(A,p,n)));
    if(incTab(x,l,n)) break;
  }
}
  
// We assume that p<2^(k-1)
// For Kyber with q=3329, we can take k=13 
void SecAddModp(uint32_t *x,uint32_t *y,uint32_t *z,uint32_t p,int k,int n)
{
  uint32_t s[n];
  SecAdd(x,y,s,k,n);  // s=x+y

  uint32_t mp[n];
  share((1 << k)-p,mp,n);

  uint32_t sp[n];
  SecAdd(s,mp,sp,k,n);  // sp=x+y-p

  uint32_t b[n];
  for(int i=0;i<n;i++)
    b[i]=-(sp[i] >> (k-1));  // b=1...1 if sp<0. b=0 if sp>=0
  for(int i=0;i<n;i++) b[i]=b[i] % (1 << k);

  uint32_t c[n];
  FullRefreshBool(b,c,k,n);

  uint32_t z2[n];
  SecAnd(s,c,z2,k,n);    // if sp<0, then b=1....1 and we select s

  uint32_t m=-1;
  b[0]=b[0] ^ m;       // b=1....1 if sp>=0. b=0 if sp<0.

  FullRefreshBool(b,c,k,n);

  uint32_t z3[n];
  SecAnd(sp,c,z3,k,n); // if sp>=0, then b=1....1 and we select sp

  for(int i=0;i<n;i++)
    z[i]=z2[i] ^ z3[i];
}
  
void testSecAddModp()
{
  int n=3,p=7,k=4;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    initTab(b,n);
    while (1)
    {
      if((xorop(a,n)<p) && (xorop(b,n)<p))
      {
	uint32_t c[n];
	SecAddModp(a,b,c,p,k,n);
	assert(((xorop(a,n)+xorop(b,n)) % p)==xorop(c,n) % p);
      }
      if(incTab(b,k,n)) break;
    }
    if(incTab(a,k,n)) break;
  }
}

void Expand(uint32_t *x,uint32_t *xp,int k,int n2,int n)
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
uint32_t GoubinAB(uint32_t A,uint32_t r,int k)
{
  uint32_t G=xorshf96();
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

    
void ConvertAB(uint32_t *A,uint32_t *z,int k,int n)
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

void testConvertAB()
{
  int n=4,l=4;
  int l2=1 << l;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    ConvertAB(a,b,l,n);
    assert(addop(a,l,n)==xorop(b,n) % l2);
    if(incTab(a,l,n)) break;
  }
}

void ConvertABModp(uint32_t *A,uint32_t *z,uint32_t p,int k,int n)
{
  if(n==1)
  {
    z[0]=A[0];
    return;
  }

  uint32_t x[n/2];
  ConvertABModp(A,x,p,k,n/2);
  uint32_t xp[n];
  Expand(x,xp,k,n/2,n);
  
  uint32_t y[(n+1)/2];
  ConvertABModp(A+n/2,y,p,k,(n+1)/2);
  uint32_t yp[n];
  Expand(y,yp,k,(n+1)/2,n);

  SecAddModp(xp,yp,z,p,k,n);
}

void refreshArithModp(uint32_t a[],uint32_t p,int n)
{
  for(int i=0;i<n-1;i++)
  {
    uint32_t tmp=xorshf96() % p; //rand();
    a[n-1]=(a[n-1] + tmp) % p;
    a[i]=(a[i] + p - tmp) % p;
  }
}

void testConvertABModp()
{
  int n=4,p=7,k=4;
  uint32_t a[n]; //,b[n];
  initTab(a,n);
  while (1)
  {
    int flag=0;
    for(int j=0;j<n;j++)
      if(a[j]>=p) flag=1;
    if(flag==0)
    {
      uint32_t z[n];
      ConvertABModp(a,z,p,k,n);
      assert(addopmodp(a,p,n)==xorop(z,n));
    }
    if(incTab(a,k,n)) break;
  }  
}

void ConvertBA(uint32_t *x,uint32_t *A,int k,int n)
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

void ConvertBAModp(uint32_t *x,uint32_t *A,uint32_t p,int k,int n)
{
  for(int i=0;i<n-1;i++) A[i]=xorshf96() % p;
  uint32_t Ap[n];
  for(int i=0;i<n-1;i++) Ap[i]=p-A[i];
  Ap[n-1]=0;

  uint32_t y[n];
  ConvertABModp(Ap,y,p,k,n);

  uint32_t z[n];
  SecAddModp(x,y,z,p,k,n);
  
  for(int i=0;i<n;i++)
    refreshBool(z,k,n);

  A[n-1]=xorop(z,n);
}


void shift(uint32_t *x,uint32_t *y,int k,int ell,int n)
{
  uint32_t z[n];
  ConvertAB(x,z,k,n);
  for(int i=0;i<n;i++)
    z[i]=z[i] >> ell;
  ConvertBA(z,y,k-ell,n);
}

void testShift()
{
  int n=3,kin=6,ell=2;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    shift(a,b,kin,ell,n);
    assert((addop(a,kin,n) >> ell)==addop(b,kin-ell,n));
    if(incTab(a,kin,n)) break;
  }
}

uint32_t th(uint32_t x,int kin)
{
  uint32_t mi=1 << (kin-2);
  uint32_t ma=3*mi;
  if((x>=mi) && (x<ma)) return 1;
  return 0;
}

uint32_t thmodp(uint32_t x,int p)
{
  if((x>p/4) && (x<=(3*p/4)))
    return 1;
  return 0;
}

void thresholdmod2k(uint32_t *x,uint32_t *b,int kin,int n)
{
  uint32_t y[n];
  y[0]=(x[0]+(1 << (kin-2))) % (1 << kin);
  for(int i=1;i<n;i++)
    y[i]=x[i];

  uint32_t z[n];
  ConvertAB(y,z,kin,n);
  for(int i=0;i<n;i++)
    b[i]=(z[i] >> (kin-1)) & 1;
}

void testThresholdmod2k()
{
  int n=3,kin=6;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    thresholdmod2k(a,b,kin,n);
    assert(th(addop(a,kin,n),kin)==xorop(b,n));
    if(incTab(a,kin,n)) break;
  }
}

void saberdecrypt(uint32_t *x,uint32_t *b, int n){
  unsigned kin = 10;
  thresholdmod2k(x, b, kin, n);
}

void thresholdmodp(uint32_t *x,uint32_t *b,int q,int kin,int n)
{
  uint32_t y[n];
  y[0]=(x[0]+(q-1)/4) % q;
  for(int i=1;i<n;i++)
    y[i]=x[i];

  uint32_t u[n];

  ConvertABModp(y,u,q,kin+1,n);

  for(int i=0;i<n;i++)
    u[i]=u[i] % (1 << kin);
  
  uint32_t v[n];
  v[0]=(1 << kin) - (q+1)/2;
  for(int i=1;i<n;i++)
    v[i]=0;

  uint32_t z[n];
  SecAdd(u,v,z,kin,n);
  
  for(int i=0;i<n;i++)
    b[i]=(z[i] >> (kin-1)) & 1;

  b[0]=b[0] ^ 1;
}


void kyberdecrypt(uint32_t *x,uint32_t *b, int n){
  unsigned kin = 13;
  thresholdmodp(x, b, 3329, kin, n);
}


void testThresholdmodp()
{
  int n=3,kin=6;
  int p=61;
  uint32_t a[n],b[n];
  initTab(a,n);
  while (1)
  {
    int flag=0;
    for(int j=0;j<n;j++)
      if(a[j]>=p) flag=1;
    if(flag==0)
    {
      thresholdmodp(a,b,p,kin,n);
      assert(thmodp(addopmodp(a,p,n),p)==xorop(b,n));
    }
    if(incTab(a,kin,n)) break;
  }
}
  
void timings32()
{
  int nt=1000;
  int k=32;

  printf("n   AB     BA     ABp    BAp    BASPOG\n");
  for(int n=2;n<14;n++)
  {
    uint32_t x[n];
    for(int j=0;j<n;j++)
      x[j]=xorshf96();

    uint32_t y[n];
    
    clock_t start=clock();
    for(int i=0;i<nt;i++)
      ConvertAB(x,y,k,n);
    clock_t end=clock();
    float dt1=((float) (end-start))/CLOCKS_PER_SEC;

    start=clock();
    for(int i=0;i<nt;i++)
      ConvertBA(x,y,k,n);
    end=clock();
    float dt2=((float) (end-start))/CLOCKS_PER_SEC;

    uint32_t p=388246907;

    start=clock();
    for(int i=0;i<nt;i++)
      ConvertABModp(x,y,p,k,n);
    end=clock();
    float dt3=((float) (end-start))/CLOCKS_PER_SEC;

    start=clock();
    for(int i=0;i<nt;i++)
      ConvertBAModp(x,y,p,k,n);
    end=clock();
    float dt4=((float) (end-start))/CLOCKS_PER_SEC;

    start=clock();
    p=3329;
    for(int i=0;i<nt;i++)
      ConvertBA_SPOG(x,y,p,n);
    end=clock();
    float dt5=((float) (end-start))/CLOCKS_PER_SEC;

    int ech=1000000;
    printf("%-3d %-6d %-6d %-6d %-6d %-6d\n",n,(int) (dt1*ech),(int) (dt2*ech),(int) (dt3*ech),(int) (dt4*ech),(int) (dt5*ech));
  }
}

void timingsKyber()
{
  int nt=1000;
  printf("Timings for Kyber decryption and encryption\n");

  for(int n=3;n<14;n++)
  {
    uint32_t x[n];
    for(int j=0;j<n;j++)
      x[j]=xorshf96();

    uint32_t y[n];

    uint32_t p=3329;
    int k=13;
    // We should have p<2^(k-1)

    clock_t start=clock();
    for(int i=0;i<nt;i++)
      thresholdmodp(x,y,p,k,n);
    clock_t end=clock();
    float dt1=((float) (end-start))/CLOCKS_PER_SEC;

    start=clock();
    for(int i=0;i<nt;i++)
      ConvertBAModp(x,y,p,k,n);
    end=clock();
    float dt2=((float) (end-start))/CLOCKS_PER_SEC;

    int ech=1000000;
    printf("%d %d %d\n",n,(int) (dt1*ech),(int) (dt2*ech));
  }
}

void timingsSaberShift()
{
  int nt=1000;

  printf("Timings Saber shift\n");
  
  for(int n=3;n<=13;n++)
  {
    uint32_t x[n];
    for(int j=0;j<n;j++)
      x[j]=xorshf96();

    uint32_t y[n];

    int kin=13;
    int ell=3;
    clock_t start=clock();

    for(int i=0;i<nt;i++)
      shift(x,y,kin,ell,n);

    clock_t end=clock();
    float dt1=((float) (end-start))/CLOCKS_PER_SEC;

    int ech=1000000;
    printf("%d %d\n",n,(int) (dt1*ech));
  }
}

void timingsSaberDecryption()
{
  int nt=1000;

  printf("Timings Saber decryption\n");
  
  for(int n=3;n<=13;n++)
  {
    uint32_t x[n];
    for(int j=0;j<n;j++)
      x[j]=xorshf96();

    uint32_t b[n];

    int kin=10;
    clock_t start=clock();

    for(int i=0;i<nt;i++)
      thresholdmod2k(x,b,kin,n);

    clock_t end=clock();
    float dt1=((float) (end-start))/CLOCKS_PER_SEC;

    int ech=1000000;
    printf("%d %d\n",n,(int) (dt1*ech));
  }
}


#ifdef TEST

int main()
{
  testSecAdd();
  testSecMul();
  testConvertBA_SPOG();
  testSecAddModp();
  testConvertAB();
  testConvertABModp();
  testShift();
  testThresholdmod2k();
  testThresholdmodp();
  timings32();
  printf("\n");
  timingsKyber();
  printf("\n");
  timingsSaberShift();
  printf("\n");
  timingsSaberDecryption();
}

#endif // TEST

