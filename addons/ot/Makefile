# USE_OT     : enable the OpenTracing filter
# OT_DEBUG   : compile the OpenTracing filter in debug mode
# OT_INC     : force the include path to libopentracing-c-wrapper
# OT_LIB     : force the lib path to libopentracing-c-wrapper
# OT_RUNPATH : add libopentracing-c-wrapper RUNPATH to haproxy executable
# OT_USE_VARS : allows the use of variables for the OpenTracing context

OT_DEFINE    =
OT_CFLAGS    =
OT_LDFLAGS   =
OT_DEBUG_EXT =
OT_PKGSTAT   =
OTC_WRAPPER  = opentracing-c-wrapper

ifneq ($(OT_DEBUG),)
OT_DEBUG_EXT = _dbg
OT_DEFINE    = -DDEBUG_OT
endif

ifeq ($(OT_INC),)
OT_PKGSTAT = $(shell pkg-config --exists $(OTC_WRAPPER)$(OT_DEBUG_EXT); echo $$?)
OT_CFLAGS = $(shell pkg-config --silence-errors --cflags $(OTC_WRAPPER)$(OT_DEBUG_EXT))
else
ifneq ($(wildcard $(OT_INC)/$(OTC_WRAPPER)/.*),)
OT_CFLAGS = -I$(OT_INC) $(if $(OT_DEBUG),-DOTC_DBG_MEM)
endif
endif

ifeq ($(OT_PKGSTAT),)
ifeq ($(OT_CFLAGS),)
$(error OpenTracing C wrapper : can't find headers)
endif
else
ifneq ($(OT_PKGSTAT),0)
$(error OpenTracing C wrapper : can't find package)
endif
endif

ifeq ($(OT_LIB),)
OT_LDFLAGS = $(shell pkg-config --silence-errors --libs $(OTC_WRAPPER)$(OT_DEBUG_EXT))
else
ifneq ($(wildcard $(OT_LIB)/lib$(OTC_WRAPPER).*),)
OT_LDFLAGS = -L$(OT_LIB) -l$(OTC_WRAPPER)$(OT_DEBUG_EXT)
ifneq ($(OT_RUNPATH),)
OT_LDFLAGS += -Wl,--rpath,$(OT_LIB)
endif
endif
endif

ifeq ($(OT_LDFLAGS),)
$(error OpenTracing C wrapper : can't find library)
endif

OPTIONS_OBJS += \
	addons/ot/src/cli.o         \
	addons/ot/src/conf.o        \
	addons/ot/src/event.o       \
	addons/ot/src/filter.o      \
	addons/ot/src/group.o       \
	addons/ot/src/http.o        \
	addons/ot/src/opentracing.o \
	addons/ot/src/parser.o      \
	addons/ot/src/pool.o        \
	addons/ot/src/scope.o       \
	addons/ot/src/util.o

ifneq ($(OT_USE_VARS),)
$(warning Please do not set the OT_USE_VARS configuration variable, as the source will probably not be able to compile!  For now, this variable can only be used for experimental purposes, and is not intended for wider use.)

OT_DEFINE     = -DUSE_OT_VARS
OPTIONS_OBJS += \
	addons/ot/src/vars.o
endif

OPTIONS_CFLAGS  += $(OT_CFLAGS) -Iaddons/ot/include
OPTIONS_LDFLAGS += $(OT_LDFLAGS)
OPTIONS_CFLAGS  += $(OT_DEFINE)
