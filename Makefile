.PHONY: clean
CFLAGS += -g3 -gdwarf-4 \
  -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes \
  -Wmissing-prototypes
nfqnltesterN : nfqnltester.o
	$(CC) $^ -o $@ -lnfnetlink -lmnl -lnetfilter_queue
nfqnltesterN1 : nfqnltester.o
	$(CC) $^ -o $@ -lnfnetlink -lmnl -lnetfilter_queue
nfqnltesterN2 : nfqnltester.o
	$(CC) $^ -o $@ -lnfnetlink -lnetfilter_queue -lmnl
nfqnltesterN3 : nfqnltester.o
	$(CC) $^ -o $@ -lmnl -lnfnetlink -lnetfilter_queue
nfqnltesterN4 : nfqnltester.o
	$(CC) $^ -o $@ -lmnl -lnfnetlink -lnetfilter_queue
nfqnltesterN5 : nfqnltester.o
	$(CC) $^ -o $@ -lnetfilter_queue -lmnl -lnfnetlink
nfqnltesterN6 : nfqnltester.o
	$(CC) $^ -o $@ -lnetfilter_queue -lnfnetlink -lmnl
clean :
	rm -f *.o nfqnltesterN*
