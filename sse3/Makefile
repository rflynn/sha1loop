# ex: set ts=8 noet:

all: sha1.asm
	nasm -f elf64 -l sha1.lst sha1.asm
	$(CC) -std=c99 -W -Wall -O3 -g -march=nocona -c -o sha-id-sse3.o sha-id-sse3.c
	$(CC) -D INTEL_SHA1_SINGLEBLOCK -o sha1-id-sse3 sha1.o sha-id-sse3.o

clean:
	$(RM) sha-id-sse3 *.o

