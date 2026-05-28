# Use 51DEGREES_SRC and possibly 51DEGREES_INC and 51DEGREES_LIB to force path
# to 51degrees v3/v4 headers and libraries if needed. Note that the SRC/INC/
# LIB/CFLAGS/LDFLAGS variables names all use 51DEGREES as the prefix,
# regardless of the version since they are mutually exclusive. The version
# (51DEGREES_VER) must be either 3 or 4, and defaults to 3 if not set.
51DEGREES_INC = $(51DEGREES_SRC)
51DEGREES_LIB = $(51DEGREES_SRC)
51DEGREES_VER = 3

ifeq ($(51DEGREES_VER),4)  # v4 here
  _51DEGREES_SRC      = $(shell find $(51DEGREES_LIB) -maxdepth 2 -name '*.c')
  OPTIONS_OBJS       += $(_51DEGREES_SRC:%.c=%.o)
  51DEGREES_CFLAGS   += -DUSE_51DEGREES_V4
  ifeq ($(USE_THREAD:0=),)
    51DEGREES_CFLAGS += -DFIFTYONEDEGREES_NO_THREADING -DFIFTYONE_DEGREES_NO_THREADING
  endif
  USE_LIBATOMIC       = implicit
endif # 51DEGREES_VER==4

ifeq ($(51DEGREES_VER),3)  # v3 here
  OPTIONS_OBJS       += $(51DEGREES_LIB)/../cityhash/city.o
  OPTIONS_OBJS       += $(51DEGREES_LIB)/51Degrees.o
  ifeq ($(USE_THREAD:0=),)
    51DEGREES_CFLAGS += -DFIFTYONEDEGREES_NO_THREADING
  else
    OPTIONS_OBJS     += $(51DEGREES_LIB)/../threading.o
  endif
else
  ifneq ($(51DEGREES_VER),4)
    $(error 51Degrees version (51DEGREES_VER) must be either 3 or 4)
  endif
endif # 51DEGREES_VER==3

OPTIONS_OBJS        += addons/51degrees/51d.o
51DEGREES_CFLAGS    += $(if $(51DEGREES_INC),-I$(51DEGREES_INC))
51DEGREES_LDFLAGS   += $(if $(51DEGREES_LIB),-L$(51DEGREES_LIB))
USE_MATH             = implicit
