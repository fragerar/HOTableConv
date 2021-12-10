CC 		  = /usr/bin/gcc
CFLAGS  = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native 
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99 
CLANG   = clang -march=native -O3 -fomit-frame-pointer -fwrapv -Qunused-arguments
RM 		  = /bin/rm


all: masked_tests

SOURCES = pack_unpack.c poly.c fips202.c verify.c cbd.c SABER_indcpa.c kem.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h 
SOURCES_GADGETS = gadgets.c old_gadgets.c random.c masked_SABER.c masked_fips202.c masked_polycomp.c
HEADERS_GADGETS = gadgets.h random.h

ORDER=1
RNG=1
MACRO = -D MASKING_ORDER=$(ORDER) -D RNG_MODE=$(RNG)


rng.o: rng.c
	$(CC) $(NISTFLAGS) -c rng.c -lcrypto -o $@ 


masked_tests: $(SOURCES_GADGETS) $(HEADERS_GADGETS) $(SOURCES) $(HEADERS) rng.o masked_tests.c
	gcc -Wall masked_tests.c $(SOURCES_GADGETS) $(SOURCES) rng.o -o masked_tests -lcrypto

bench: $(SOURCES_GADGETS) $(HEADERS_GADGETS) $(SOURCES) $(HEADERS) rng.o benchmarks.c cpucycles.c
	gcc -Wall benchmarks.c cpucycles.c -O3 $(SOURCES_GADGETS) $(SOURCES) $(MACRO) rng.o -o bench -lcrypto

# fips202.o: fips202.c
# 	$(CLANG) -c $^ -o $@

.PHONY: clean test

clean:
	-$(RM) -f *.o
	-$(RM) -f masked_tests
	-$(RM) -f bench

