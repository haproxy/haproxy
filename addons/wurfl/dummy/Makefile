# makefile for dummy wurfl library
# builds shared library
# installs it in /usr/lib/ with header file wurfl.h in /usr/include/wurfl
#
# install needs to be run as root

build: libwurfl.a

libwurfl.a: dummy-wurfl.o
	ar rv $@ $<

clean:
	rm -rf *.a *.o
