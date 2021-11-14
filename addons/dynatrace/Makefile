
OPTIONS_OBJS += \
	addons/dynatrace/src/filter.o

OPTIONS_CFLAGS  += $(if $(DYNATRACE_INC),-I$(DYNATRACE_INC)) -Iaddons/dynatrace/include
OPTIONS_LDFLAGS += $(if $(DYNATRACE_LIB),-L$(DYNATRACE_LIB)) -lonesdk_static
