#ifndef CONVBA2014_H
#define CONVBA2014_H

void ConvertAB(uint32_t *A,uint32_t *z,int k,int n);
void ConvertABModp(uint32_t *A,uint32_t *z,uint32_t p,int n);
void ConvertBA(uint32_t *x,uint32_t *A,int n);
void ConvertBAModp(uint32_t *x,uint32_t *A,uint32_t p,int n);
void shift(uint32_t *x,uint32_t *y,int kin,int ell,int n);
void thresholdmod2k(uint32_t *x,uint32_t *b,int kin,int n);
void ConvertBA_SPOG(uint32_t *x,uint32_t *y,int p,int n);
void kyberdecrypt(uint32_t *x,uint32_t *b, int n);
void saberdecrypt(uint32_t *x,uint32_t *b, int n);
#endif
