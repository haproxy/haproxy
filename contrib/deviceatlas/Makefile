# makefile for dummy DeviceAtlas library
#
# To enable the DeviceAtlas module support, the following are needed
# make TARGET=<target> DEVICEATLAS_SRC=./contrib/deviceatlas USE_PCRE=1 USE_DEVICEATLAS=1

build: libda.a

libda.a: dac.o
	ar rv $@ $<

clean:
	rm -rf *.a *.o
