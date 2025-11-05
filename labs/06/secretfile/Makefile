# -----------------------------------------------------------------------------
# Author:       M. Rennhard
# Date:         08.07.2024
# Description:  Makefile for secretfile program
# -----------------------------------------------------------------------------

C       = gcc
CFLAGS  = -g

all:
		make server
		make client
		cp *.txt /tmp
		
server:	server.o
		$(C) server.o -o $@

server.o:	server.c common.h Makefile
		$(C) -c $(CFLAGS) server.c -o $@

client:	client.o
		$(C) client.o -o $@

client.o:	client.c common.h Makefile
		$(C) -c $(CFLAGS) client.c -o $@  

clean:
		rm -f *.o
		rm -f server
		rm -f client
		rm -f /tmp/public.txt
		rm -f /tmp/secret.txt

build:
		touch *.c*
		make clean
		make all

