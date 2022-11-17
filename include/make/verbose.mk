# verbosity: pass V=1 for verbose shell invocation
V = 0
Q = @
ifeq ($V,1)
Q=
endif

# Some common commands such as CC/LD/AR are redefined with a cmd_ equivalent
# and are either mapped to a silent rule just indicating what is being done,
# or to themselves depending on the verbosity level.
ifeq ($V,1)
cmd_CC = $(CC)
cmd_LD = $(LD)
cmd_AR = $(AR)
else
ifeq (3.81,$(firstword $(sort $(MAKE_VERSION) 3.81)))
# 3.81 or above
cmd_CC = $(info $   CC      $@) $(Q)$(CC)
cmd_LD = $(info $   LD      $@) $(Q)$(LD)
cmd_AR = $(info $   AR      $@) $(Q)$(AR)
else
# 3.80 or older
cmd_CC = $(Q)echo "  CC      $@";$(CC)
cmd_LD = $(Q)echo "  LD      $@";$(LD)
cmd_AR = $(Q)echo "  AR      $@";$(AR)
endif
endif
