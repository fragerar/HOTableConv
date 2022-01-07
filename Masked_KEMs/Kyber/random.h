#ifndef RANDOM_H
#define RANDOM_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#ifndef RNG_MODE
#define RNG_MODE 1
#endif

//#define COUNT
#ifdef COUNT
extern uint64_t count_rand;
#endif

uint16_t rand16(void);
uint32_t rand32(void);
uint64_t rand64(void);
void rand_q(uint16_t v[2]);
uint16_t uniform_rand16(uint16_t max_val);
#endif