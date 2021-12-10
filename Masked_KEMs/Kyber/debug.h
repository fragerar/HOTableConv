#ifndef TEST_H
#define TEST_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include "poly.h"
#include "gadgets.h"

void print_poly(poly* p);
void unmask_poly(masked_poly* mp, poly* p);
void compare_poly(poly* a, poly* b);
void print_masked_poly(masked_poly* mp);
void print_masked_polyvec(masked_polyvec* mp);
void print_polyvec(polyvec* pv);

#endif

