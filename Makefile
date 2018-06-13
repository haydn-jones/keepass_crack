CC = gcc
CFLAGS = -g -Wall

all: keepcrack keepcrack_func decrypt

keepcrack_func: keepcrack_func.c
	$(CC) $(CFLAGS) -c $@.c
decrypt: decrypt.c
	$(CC) $(CFLAGS) -c $@.c
keepcrack: keepcrack.c keepcrack_func decrypt
	$(CC) $(CFLAGS) $@.c keepcrack_func.o decrypt.o -o $@ -lcrypto
clean:
	rm -f keepcrack *.o
