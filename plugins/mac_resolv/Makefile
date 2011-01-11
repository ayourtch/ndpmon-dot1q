# Generated automatically from Makefile.in by configure.
FLAGS=-Wall -pedantic -I../.. -O2 -I/usr/include -I/usr/include -I/usr/include  -D_LINUX_
CC=gcc
LIB= -L/usr/lib -lxml2 -L/usr/lib -lpcap -L/usr/lib -lcrypto
all: mac_resolv.o

clean: 
	-rm -rf *~ *.o 

mac_resolv.o: mac_resolv.c
	-./make-manuf
	$(CC) $(FLAGS) `xml2-config  --cflags` -c mac_resolv.c -o mac_resolv.o
