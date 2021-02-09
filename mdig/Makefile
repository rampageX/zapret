CC ?= gcc
CFLAGS += -std=c99 -s -O3
LIBS = -lpthread
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS) $(LIBS)

clean:
	rm -f mdig *.o
