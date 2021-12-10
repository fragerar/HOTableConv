#ifndef GADGETS_H
#define GADGETS_H

#ifndef MASKING_ORDER
#define MASKING_ORDER 6
#endif

typedef struct Masked {int shares[MASKING_ORDER+1];} Masked;


/* New gadgets from our paper */

void opt_Z16_to_4bits(Masked* x, Masked* y);
void shift1(Masked* z, Masked* a, unsigned k);
void masked_shift(Masked* x, Masked* y, unsigned k, unsigned l);
void triple_shift1(Masked* z, Masked* a, unsigned k);
void convert_2_l_to_1bit_bool(Masked* x, Masked* b, unsigned l);
void kyber_decryption(Masked* x, Masked* b);
void convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q);
void optimized_convert_B2A(Masked* x, Masked* y, unsigned k, unsigned q);






/* Existing gadgets and utils*/
void arithmetic_refresh(Masked* x, unsigned q);
void boolean_refresh(Masked* x, unsigned k);
void refresh_masks_n(int* x, int* y, const int N);
void goubin_bool_arith(int* bool_x, int* arith_x);
void HO_bool_arith(int* bool_x, int* arith_x, const int N);
void exponential_B2A(Masked* x, Masked *y);

void print_masked_arith(Masked* x, int q);
void print_masked_bool(Masked* y);



#endif 