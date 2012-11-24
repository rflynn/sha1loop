LDFLAGS=-g -static
CC=gcc
CFLAGS=-std=c99 -O3 -g -Wall -march=nocona -fomit-frame-pointer

#CFLAGS=-std=c99 -O2 -g -march=pentium4 -fno-alias -unroll1
#CC=icc

EXE=time-sha1 test-sha1 sha1-id-sse2

all: $(EXE)

clean:
	rm -f $(EXE) *.o

time-sha1: time-sha1.o sha1.o

test-sha1: test-sha1.o sha1.o

sha1-id-sse2: sha1-id-sse2.o sha1.o

test: test-sha1
	./test-sha1
