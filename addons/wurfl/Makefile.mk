# Use WURFL_SRC and possibly WURFL_INC and WURFL_LIB to force path
# to WURFL headers and libraries if needed.
WURFL_INC = $(WURFL_SRC)
WURFL_LIB = $(WURFL_SRC)
OPTIONS_OBJS    += addons/wurfl/wurfl.o
WURFL_CFLAGS     = $(if $(WURFL_INC),-I$(WURFL_INC))
ifneq ($(WURFL_DEBUG),)
  WURFL_CFLAGS  += -DWURFL_DEBUG
endif
ifneq ($(WURFL_HEADER_WITH_DETAILS),)
  WURFL_CFLAGS  += -DWURFL_HEADER_WITH_DETAILS
endif
WURFL_LDFLAGS    = $(if $(WURFL_LIB),-L$(WURFL_LIB)) -lwurfl
