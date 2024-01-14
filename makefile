CC= gcc
G++ = g++
GPPFLAGS =-shared -fPIC -g
all: libinjector pwnCheat.so

libinjector: injector/injector.h injector/libinjector.a injector/main.c
	$(CC) -o $@ injector/main.c injector/libinjector.a 

pwnCheat.so: pwnCheat/pwnCheat.h pwnCheat/main.cpp
	$(G++) $(GPPFLAGS) -o $@ pwnCheat/main.cpp
clean:
	rm -rf libinjector
	rm -rf pwnCheat.so
