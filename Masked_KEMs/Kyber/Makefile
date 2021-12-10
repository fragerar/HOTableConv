CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c masked_indcpa.c masked_poly.c masked_polyvec.c masked_fips202.c debug.c masked_kem.c random.c polycomp.c
SOURCES_GADGETS = Kyber_gadgets.c gadgets.c 
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
SOURCESNINETIES = $(SOURCES) sha256.c sha512.c aes256ctr.c symmetric-aes.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h debug.h masked_kem.h random.h
HEADERS_GADGETS = gadgets.h
HEADERSKECCAK = $(HEADERS) fips202.h
HEADERSNINETIES = $(HEADERS) aes256ctr.h sha2.h

ORDER=1
RNG=1
MACRO = -D KYBER_MASKING_ORDER=$(ORDER) -D RNG_MODE=$(RNG)

all: main bench

main: $(SOURCESKECCAK) $(HEADERSKECCAK) $(SOURCES_GADGETS) $(HEADERS_GADGETS) main.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES_GADGETS) $(SOURCESKECCAK) randombytes.c main.c -o main_kyber768
 
bench: $(SOURCESKECCAK) $(HEADERSKECCAK) $(SOURCES_GADGETS) $(HEADERS_GADGETS) benchmarks.c randombytes.c cpucycles.c cpucycles.h
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCES_GADGETS) $(SOURCESKECCAK) $(MACRO) randombytes.c benchmarks.c cpucycles.c -o bench
clean:
	-$(RM) -rf main_kyber768
	-$(RM) -rf bench
