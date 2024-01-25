# makefile for dummy DeviceAtlas library
#
# To enable the DeviceAtlas module support, the following are needed
# make TARGET=<target> DEVICEATLAS_SRC=addons/deviceatlas/dummy USE_DEVICEATLAS=1

build: libda.a

libda.a: dac.o
	ar rv $@ $<

clean:
	rm -rf *.a *.o
