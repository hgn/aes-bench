
CC	   = gcc
CFLAGS = -Wall -g -O0 -W -pipe -lrt -lm -lssl

.SUFFIXES:
.SUFFIXES: .o .c

aes-bench: aes-bench.c
	        $(CC) $(CFLAGS) $@.c $(LDFLAGS) -o $@

clean:
	rm -f aes-bench core
