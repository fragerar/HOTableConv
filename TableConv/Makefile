ORDER = 7
RUNS = 10000
RNG = 1

MACRO = -D MASKING_ORDER=$(ORDER) -D ITER=$(RUNS) -D RNG_MODE=$(RNG)
SOURCES = new_gadgets.c old_gadgets.c random.c tests.c convba_2014.c 
HEADERS = gadgets.h random.h
SOURCES_BENCH = benchmarks.c cpucycles.c 

main: $(SOURCES) $(HEADERS) main.c
	gcc -Wall main.c $(SOURCES) -o main  

bench: $(SOURCES) $(HEADERS) $(SOURCES_BENCH)
	gcc -Wall -O2 -march=native $(SOURCES) $(SOURCES_BENCH) $(MACRO) -o bench 

clean:
	rm -f main bench