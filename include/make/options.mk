# this contains various functions and macros used to manipulate USE_* options
# and their flags

# Depending on the target platform, some options are set, as well as some
# CFLAGS and LDFLAGS. All variables pre-set here will not appear in the build
# options string. They may be set to any value, but are historically set to
# "implicit" which eases debugging. You should not have to change anything
# there unless you're adding support for a new platform.
default_opts = $(foreach name,$(1),$(eval $(name)=implicit))

# Return USE_xxx=$(USE_xxx) if the variable was set from the environment or the
# command line.
ignore_implicit = $(if $(subst environment,,$(origin $(1))),         \
                       $(if $(subst command line,,$(origin $(1))),,  \
                            $(1)=$($(1))),                           \
                       $(1)=$($(1)))                                 \

# This macro collects all USE_* values except those set to "implicit". This
# is used to report a list of all flags which were used to build this version.
# Do not assign anything to it.
build_options   = $(foreach opt,$(use_opts),$(call ignore_implicit,$(opt)))

# Make a list of all known features with +/- prepended depending on their
# activation status. Must be a macro so that dynamically enabled ones are
# evaluated with their current status.
build_features  = $(foreach opt,$(patsubst USE_%,%,$(sort $(use_opts))),$(if $(USE_$(opt):0=),+$(opt),-$(opt)))

# This returns a list of -DUSE_* for all known USE_* that are set to anything
# neither empty nor '0'.
opts_as_defines = $(foreach opt,$(use_opts),$(if $($(opt):0=),-D$(opt),))

# Lists all enabled or disabled options without the "USE_" prefix
enabled_opts    = $(foreach opt,$(patsubst USE_%,%,$(use_opts)),$(if $(USE_$(opt):0=),$(opt),))
disabled_opts   = $(foreach opt,$(patsubst USE_%,%,$(use_opts)),$(if $(USE_$(opt):0=),,$(opt)))

# preset all XXX_{INC,LIB,CFLAGS,LDFLAGS,SRC} variables to empty for $1=XXX
reset_opt_vars = $(foreach name,INC LIB CFLAGS LDFLAGS SRC,$(eval $(1)_$(name)=))

# preset all variables for all supported build options among use_opts
reset_opts_vars = $(foreach opt,$(patsubst USE_%,%,$(use_opts)),$(call reset_opt_vars,$(opt)))

# append $(1)_{C,LD}FLAGS into OPTIONS_{C,LD}FLAGS if not empty
define collect_opt_flags
  ifneq ($$($(1)_CFLAGS),)
    OPTIONS_CFLAGS += $$($(1)_CFLAGS)
  endif
  ifneq ($$($(1)_LDFLAGS),)
    OPTIONS_LDFLAGS += $$($(1)_LDFLAGS)
  endif
endef

# collect all enabled USE_foo's foo_{C,LD}FLAGS into OPTIONS_{C,LD}FLAGS
collect_opts_flags = $(foreach opt,$(enabled_opts),$(eval $(call collect_opt_flags,$(opt))))

# Check that any USE_* variable that was forced actually exist. For this we'll
# build a list of the MAKEOVERRIDES variables that start with USE_*, and keep
# the ones that do not match any of the patterns built by appending '=%' to all
# use_opts. The outstanding ones are thus unknown and each of them produces a
# warning.
warn_unknown_options =                                                       \
    $(foreach unknown,                                                       \
              $(filter-out $(foreach opt,$(use_opts),$(opt:==%)),            \
                           $(foreach opt,$(MAKEOVERRIDES),                   \
                                     $(strip $(filter USE_%,$(opt))))),      \
              $(call $(complain),ignoring unknown build option: $(unknown)))
