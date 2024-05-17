.PHONY: clean
CFLAGS += -g3 -gdwarf-4 \
  -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes \
  -Wmissing-prototypes
nfqnltester : nfqnltester.o
	$(CC) $^ -o $@ -lmnl -lnetfilter_queue
nfqnltester1 : nfqnltester.o
	$(CC) $^ -o $@ -lnfnetlink -lmnl -lnetfilter_queue
nfqnltester2 : nfqnltester.o
	$(CC) $^ -o $@ -lnfnetlink -lnetfilter_queue -lmnl
nfqnltester3 : nfqnltester.o
	$(CC) $^ -o $@ -lmnl -lnfnetlink -lnetfilter_queue
nfqnltester4 : nfqnltester.o
	$(CC) $^ -o $@ -lmnl -lnfnetlink -lnetfilter_queue
nfqnltester5 : nfqnltester.o
	$(CC) $^ -o $@ -lnetfilter_queue -lmnl -lnfnetlink
nfqnltester6 : nfqnltester.o
	$(CC) $^ -o $@ -lnetfilter_queue -lnfnetlink -lmnl
nfqnltester7 : nfqnltester.o
	$(CC) $^ -o $@ -lnetfilter_queue -lmnl
clean :
	rm -f *.o *.d
	find . -name "nfqnltester*" -perm 755 | xargs rm -v
