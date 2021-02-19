CC ?= gcc
CFLAGS += -std=c99 -s -O3
LIBS = 
SRC_FILES = *.c

all: ip2net
bsd: all
mac: all

ip2net: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

clean:
	rm -f ip2net *.o
