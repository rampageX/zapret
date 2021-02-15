CC ?= gcc
CFLAGS += -std=c99 -s -O3
LIBS = -lz
SRC_FILES = *.c

all: tpws

tpws: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

bsd: $(SRC_FILES)
	$(CC) $(CFLAGS) -Iepoll-shim/include -o tpws $(SRC_FILES) epoll-shim/src/*.c $(LDFLAGS) $(LIBS)

clean:
	rm -f tpws *.o
