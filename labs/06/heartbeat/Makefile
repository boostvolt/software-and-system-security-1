# -----------------------------------------------------------------------------
# Author:       M. Rennhard
# Date:         08.07.2024
# Description:  Makefile for heartbeat program
# -----------------------------------------------------------------------------

C       = gcc
CFLAGS  = -g -fstack-protector-all

all:
		make server
		make client
		
server:	server.o common.o 
		$(C) server.o common.o -o $@

server.o:	server.c common.h Makefile
		$(C) -c $(CFLAGS) server.c -o $@

client:	client.o common.o
		$(C) client.o common.o -o $@

client.o:	client.c common.h Makefile
		$(C) -c $(CFLAGS) client.c -o $@  

common.o:	common.c common.h Makefile
		$(C) -c $(CFLAGS) common.c -o $@
		
clean:
		rm -f *.o
		rm -f server
		rm -f client

build:
		touch *.c*
		make clean
		make all

