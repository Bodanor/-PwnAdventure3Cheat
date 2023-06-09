CC= gcc
G++ = g++
GPPFLAGS =-shared -fPIC -g
all: libinjector libGameLogic.so

libinjector: injector/injector.h injector/libinjector.a injector/main.c
	$(CC) -o $@ injector/main.c injector/libinjector.a 

libGameLogic.so: libGameLogic/libGameLogic.h libGameLogic/main.cpp
	$(G++) $(GPPFLAGS) -o $@ libGameLogic/main.cpp
clean:
	rm -rf libinjector
	rm -rf libGameLogic.so
