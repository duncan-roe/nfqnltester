.PHONY: clean
SRCS = $(wildcard *.c)
PROG = $(shell basename $$PWD)
LIBS = -lmnl -lnetfilter_queue -lnfnetlink
OBJ = $(SRCS:.c=.o)
CFLAGS += -g3 -gdwarf-4 \
  -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes \
  -Wmissing-prototypes
$(PROG) : $(OBJ)
	$(CC) $^ -o $@ $(LIBS)
clean :
	rm -f *.o *.d $(PROG)

# Auto dependency stuff (from info make)
%.d: %.c
	$(CC) -MM -MT $(@:.d=.o) -MT $@ $(CPPFLAGS) $< -o $@
ifneq ($(MAKECMDGOALS),clean)
-include $(SRCS:.c=.d)
endif
