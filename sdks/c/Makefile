CC ?= gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Iinclude

all: ../../bin/atp-c

../../bin/atp-c: src/advancetether.c src/cli.c include/advancetether.h
	mkdir -p ../../bin
	$(CC) $(CFLAGS) src/advancetether.c src/cli.c -o ../../bin/atp-c

test: ../../bin/atp-c
	../../bin/atp-c --self-test

clean:
	rm -f ../../bin/atp-c
