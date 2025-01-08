# verbosity: pass V=1 for verbose shell invocation
V = 0
Q = @
ifeq ($V,1)
Q=
endif

# Some common commands such as CC/LD/AR are redefined with a cmd_ equivalent
# and are either mapped to a silent rule just indicating what is being done,
# or to themselves depending on the verbosity level. The qinfo macro is meant
# to be called using $(call qinfo,<string>) as a prefix, and will be either
# empty or that <string>; the caller must pass the alignment spaces (9 chars
# total).
ifeq ($V,1)
cmd_CC = $(CC)
cmd_CXX = $(CXX)
cmd_LD = $(LD)
cmd_AR = $(AR)
cmd_MAKE = +$(MAKE)
qinfo =
else
ifeq (3.81,$(firstword $(sort $(MAKE_VERSION) 3.81)))
# 3.81 or above
cmd_CC = $(info $   CC      $@) $(Q)$(CC)
cmd_CXX = $(info $   CXX     $@) $(Q)$(CXX)
cmd_LD = $(info $   LD      $@) $(Q)$(LD)
cmd_AR = $(info $   AR      $@) $(Q)$(AR)
cmd_MAKE = $(info $   MAKE    $@) $(Q)+$(MAKE)
qinfo = $(info $(1) $@) $(Q)
else
# 3.80 or older
cmd_CC = $(Q)echo "  CC      $@";$(CC)
cmd_CXX = $(Q)echo "  CXX     $@";$(CXX)
cmd_LD = $(Q)echo "  LD      $@";$(LD)
cmd_AR = $(Q)echo "  AR      $@";$(AR)
cmd_MAKE = $(Q)echo "  MAKE    $@";$(MAKE)
qinfo = $(Q)echo "$(1) $@";
endif
endif
