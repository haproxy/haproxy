# DEVICEATLAS_SRC     : DeviceAtlas API source root path


OS              := $(shell uname -s)
OBJS            := dadwsch.o
CFLAGS          := -g -O2
LDFLAGS         :=

CURL_CONFIG     := curl-config
CURLDIR         := $(shell $(CURL_CONFIG) --prefix 2>/dev/null || echo /usr/local)
CURL_INC        := $(CURLDIR)/include
CURL_LIB        := $(CURLDIR)/lib
CURL_LDFLAGS    := $(shell $(CURL_CONFIG) --libs 2>/dev/null || echo -L /usr/local/lib -lcurl)

PCRE2_CONFIG    := pcre2-config
PCRE2DIR        := $(shell $(PCRE2_CONFIG) --prefix 2>/dev/null || echo /usr/local)
PCRE2_INC       := $(PCRE2DIR)/include
PCRE2_LIB       := $(PCRE2DIR)/lib
PCRE2_LDFLAGS   := $(shell $(PCRE2_CONFIG) --libs8 2>/dev/null || echo /usr/local)

ifeq ($(DEVICEATLAS_SRC),)
dadwsch:    dadwsch.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

LDFLAGS         += -lda
else
DEVICEATLAS_INC = $(DEVICEATLAS_SRC)
DEVICEATLAS_LIB = $(DEVICEATLAS_SRC)
CFLAGS          += -DDA_REGEX_HDR=\"dac_pcre2.c\" -DDA_REGEX_TAG=2
CFLAGS          += -DMOBI_CURL -DMOBI_CURLSSET -DMOBI_GZ -DMOBI_ZIP
CFLAGS          += -I$(DEVICEATLAS_INC) -I$(CURL_INC) -I$(PCRE2DIR)
LDFLAGS         += $(CURL_LDFLAGS) $(PCRE2_LDFLAGS) -lz -lzip -lpthread

dadwsch:    dadwsch.c $(DEVICEATLAS_SRC)/dac.c $(DEVICEATLAS_SRC)/dasch.c $(DEVICEATLAS_SRC)/dadwarc.c $(DEVICEATLAS_SRC)/dadwcom.c $(DEVICEATLAS_SRC)/dadwcurl.c $(DEVICEATLAS_SRC)/json.c $(DEVICEATLAS_SRC)/Os/daunix.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
endif

ifeq ($(OS), Linux)
LDFLAGS         += -lrt
endif
ifeq ($(OS), SunOS)
LDFLAGS         += -lrt
endif

clean:
		rm -f *.o
		rm -f $(DEVICEATLAS_LIB)*.o
		rm -f dadwsch
