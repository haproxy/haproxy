# DEVICEATLAS_SRC     : DeviceAtlas API source root path


CXX             := c++
CXXLIB          := -lstdc++

CURL_CONFIG     := curl-config
CURLDIR         := $(shell $(CURL_CONFIG) --prefix 2>/dev/null || echo /usr/local)
CURL_INC        := $(CURLDIR)/include
CURL_LIB        := $(CURLDIR)/lib
CURL_LDFLAGS    := $(shell $(CURL_CONFIG) --libs 2>/dev/null || echo -L /usr/local/lib -lcurl)

ifeq ($(DEVICEATLAS_SRC),)
OPTIONS_LDFLAGS         += -lda
else
DEVICEATLAS_INC = $(DEVICEATLAS_SRC)
DEVICEATLAS_LIB = $(DEVICEATLAS_SRC)
OPTIONS_LDFLAGS += $(CURL_LDFLAGS) -lz -lzip -lpthread
OPTIONS_CFLAGS  += -DDATLAS_CURL -DDATLAS_CURLSSET -DDATLAS_GZ -DDATLAS_ZIP
OPTIONS_CFLAGS  += -I$(DEVICEATLAS_INC) -I$(CURL_INC)
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
