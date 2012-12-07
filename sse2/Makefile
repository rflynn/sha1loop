UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
LDFLAGS=-g # OS X
CC=clang # 5.1M/sec vs gcc 4.2.1 4.6M/sec2
else
LDFLAGS=-g -lpthread
endif

#CC=gcc
CFLAGS=-std=gnu99 -O3 -W -Wall -march=core2 -mtune=core2 -msse2 -fomit-frame-pointer
#CC=/Users/rflynn93/src/llvm/Debug+Asserts/bin/clang
#CFLAGS=-std=c99 -O3 -g -W -Wall -march=corei7 -mtune=corei7 -msse2 -fomit-frame-pointer

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
