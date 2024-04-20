# Makefile
# Compiler to be used
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror

all: server client

server: server.c server.h
	$(CC) $(CFLAGS) -o server server.c -pthread

client: client.c client.h
	$(CC) $(CFLAGS) -o client client.c -pthread

clean:
	rm -f server client
