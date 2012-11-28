# ex: set ts=8 noet:

all: sha1.asm
	nasm -f elf -l sha1.lst sha1.asm
	$(CC) -o sha1 sha1.o
