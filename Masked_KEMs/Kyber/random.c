#include "random.h"
#include "params.h"

#if RNG_MODE == 1
static unsigned x=123456789, y=362436069, z=521288629;
#endif


uint32_t rand32(){

#ifdef COUNT
  count_rand++;
#endif

#if RNG_MODE == 1
  unsigned t;

  x ^= x << 16;
  x ^= x >> 5;
  x ^= x << 1;

  t = x;
  x = y;
  y = z;
  z = t ^ x ^ y; 
  return z;
#elif RNG_MODE == 2
  return rand();
#elif RNG_MODE == 0
  return 0;
#endif

}

uint16_t rand16(){
  return (uint16_t)rand32()&(0xFFFF);
}

uint64_t rand64(){

  return ((uint64_t)rand32() << 32) + (uint64_t)rand32();
}

void rand_q(uint16_t v[2]){
  uint32_t r;
  do{
    r = rand32();
  } while(r > (387U * KYBER_Q*KYBER_Q));
  r = r%(KYBER_Q*KYBER_Q);
  v[0] = r%(KYBER_Q);
  v[1] = r/KYBER_Q;
}
