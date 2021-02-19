CC ?= gcc
CFLAGS += -std=c99 -s -O3 -Wno-address-of-packed-member -Wno-switch
LIBS = -lnetfilter_queue -lnfnetlink -lz
LIBS_BSD = -lz
SRC_FILES = *.c

all: nfqws

nfqws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

mac: bsd
bsd: $(SRC_FILES)
	$(CC) $(CFLAGS) -o dvtws $(SRC_FILES) $(LDFLAGS) $(LIBS_BSD)

clean:
	rm -f nfqws dvtws *.o
