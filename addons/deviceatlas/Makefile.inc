# DEVICEATLAS_SRC     : DeviceAtlas API source root path


CXX             := c++
CXXLIB          := -lstdc++

ifeq ($(DEVICEATLAS_SRC),)
OPTIONS_LDFLAGS         += -lda
else
DEVICEATLAS_INC = $(DEVICEATLAS_SRC)
DEVICEATLAS_LIB = $(DEVICEATLAS_SRC)
OPTIONS_LDFLAGS += -lpthread
OPTIONS_CFLAGS  += -I$(DEVICEATLAS_INC)
ifeq ($(DEVICEATLAS_NOCACHE),)
CXXFLAGS        := $(OPTIONS_CFLAGS) -std=gnu++11
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/dacache.o
OPTIONS_LDFLAGS += $(CXXLIB)
else
OPTIONS_CFLAGS  += -DAPINOCACHE
endif
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/dac.o
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/json.o
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/dasch.o
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/dadwarc.o
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/dadwcom.o
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/dadwcurl.o
OPTIONS_OBJS    += $(DEVICEATLAS_SRC)/Os/daunix.o
endif

addons/deviceatlas/dummy/%.o:    addons/deviceatlas/dummy/%.cpp
	$(cmd_CXX) $(CXXFLAGS) -c -o $@ $<
