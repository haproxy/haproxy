# USE_OTEL      : enable the OpenTelemetry filter
# OTEL_DEBUG    : compile the OpenTelemetry filter in debug mode
# OTEL_INC      : force the include path to libopentelemetry-c-wrapper
# OTEL_LIB      : force the lib path to libopentelemetry-c-wrapper
# OTEL_RUNPATH  : add libopentelemetry-c-wrapper RUNPATH to haproxy executable

OTEL_DEFINE    =
OTEL_CFLAGS    =
OTEL_LDFLAGS   =
OTEL_DEBUG_EXT =
OTEL_PKGSTAT   =
OTELC_WRAPPER  = opentelemetry-c-wrapper

ifneq ($(OTEL_DEBUG:0=),)
OTEL_DEBUG_EXT = _dbg
OTEL_DEFINE    = -DDEBUG_OTEL
endif

ifeq ($(OTEL_INC),)
OTEL_PKGSTAT = $(shell pkg-config --exists $(OTELC_WRAPPER)$(OTEL_DEBUG_EXT); echo $$?)
OTEL_CFLAGS  = $(shell pkg-config --silence-errors --cflags $(OTELC_WRAPPER)$(OTEL_DEBUG_EXT))
else
ifneq ($(wildcard $(OTEL_INC)/$(OTELC_WRAPPER)/.*),)
OTEL_CFLAGS = -I$(OTEL_INC) $(if $(OTEL_DEBUG),-DOTELC_DBG_MEM)
endif
endif

ifeq ($(OTEL_PKGSTAT),)
ifeq ($(OTEL_CFLAGS),)
$(error OpenTelemetry C wrapper : can't find headers)
endif
else
ifneq ($(OTEL_PKGSTAT),0)
$(error OpenTelemetry C wrapper : can't find package)
endif
endif

ifeq ($(OTEL_LIB),)
OTEL_LDFLAGS = $(shell pkg-config --silence-errors --libs $(OTELC_WRAPPER)$(OTEL_DEBUG_EXT))
else
ifneq ($(wildcard $(OTEL_LIB)/lib$(OTELC_WRAPPER).*),)
OTEL_LDFLAGS = -L$(OTEL_LIB) -l$(OTELC_WRAPPER)$(OTEL_DEBUG_EXT)
ifneq ($(OTEL_RUNPATH),)
OTEL_LDFLAGS += -Wl,--rpath,$(OTEL_LIB)
endif
endif
endif

ifeq ($(OTEL_LDFLAGS),)
$(error OpenTelemetry C wrapper : can't find library)
endif

OPTIONS_OBJS += \
	addons/otel/src/filter.o \
	addons/otel/src/parser.o

OTEL_CFLAGS := $(OTEL_CFLAGS) -Iaddons/otel/include $(OTEL_DEFINE)
