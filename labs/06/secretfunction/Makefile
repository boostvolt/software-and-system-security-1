# -----------------------------------------------------------------------------
# Author:       M. Rennhard
# Date:         08.07.2024
# Description:  Makefile for secretfunction program
# -----------------------------------------------------------------------------

C       = gcc 
CFLAGS  = -g

all:
			make secretfunction
		
secretfunction:	secretfunction.o
			$(C) secretfunction.o -o $@

secretfunction.o:	secretfunction.c Makefile
			$(C) -c $(CFLAGS) secretfunction.c -o $@

clean:
			rm -f *.o
			rm -f secretfunction

build:
			touch *.c*
			make clean
			make all

