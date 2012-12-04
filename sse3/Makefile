# ex: set ts=8 noet:

all: sha1.asm
	nasm -f elf64 -l sha1.lst sha1.asm
	$(CC) -std=c99 -W -Wall -O3 -g -march=nocona -c -o sha1-id-sse3.o sha1-id-sse3.c
	$(CC) -D INTEL_SHA1_SINGLEBLOCK -o sha1-id-sse3 sha1.o sha1-id-sse3.o

osx: sha1.asm
	./nasm -f macho64 -l sha1.lst sha1.asm
	$(CC) -std=c99 -W -Wall -O3 -g -msse3 -c -o sha1-id-sse3.o sha1-id-sse3.c
	$(CC) -D INTEL_SHA1_SINGLEBLOCK -o sha1-id-sse3 sha1.o sha1-id-sse3.o

clean:
	$(RM) sha1-id-sse3 *.o

