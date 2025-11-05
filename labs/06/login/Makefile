# -----------------------------------------------------------------------------
# Author:       M. Rennhard
# Date:         08.07.2024
# Description:  Makefile for login program
# -----------------------------------------------------------------------------

C       = gcc
CFLAGS  = -g -fstack-protector-all

all:
		make login
		
login:		login.o
		$(C) login.o -o $@

login.o:	login.c Makefile
		$(C) -c $(CFLAGS) login.c -o $@

clean:
		rm -f *.o
		rm -f login

build:
		touch *.c*
		make clean
		make all

