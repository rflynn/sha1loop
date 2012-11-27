
# ex: set ts=8 noet:

all:
	gcc -std=c99 -O3 -static -Wall -march=nocona -fomit-frame-pointer -o sha-id sha-id.c sha1.c

