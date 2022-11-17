# WARNING: Do not change cc-opt, cc-opt-alt or cc-warning without checking if
#          clang bug #49364 is fixed. stderr is redirected to /dev/null on
#          purpose, to work around a clang 11 bug that crashes if stderr is
#          redirected to stdin.
#
# Function used to detect support of a given option by the compiler.
# Usage: CFLAGS += $(call cc-opt,option). Eg: $(call cc-opt,-fwrapv)
# Note: ensure the referencing variable is assigned using ":=" and not "=" to
#       call it only once.
cc-opt = $(shell set -e; if $(CC) -Werror $(1) -E -xc - -o /dev/null </dev/null >&0 2>/dev/null; then echo "$(1)"; fi;)

# same but tries with $2 if $1 is not supported
cc-opt-alt = $(if $(shell set -e; if $(CC) -Werror $(1) -E -xc - -o /dev/null </dev/null >&0 2>/dev/null; then echo 1;fi),$(1),$(call cc-opt,$(2)))

# validate a list of options one at a time
cc-all-opts  = $(foreach a,$(1),$(call cc-opt,$(a)))

# try to pass plenty of options at once, take them on success or try them
# one at a time on failure and keep successful ones. This is handy to quickly
# validate most common options.
cc-all-fast = $(if $(call cc-opt,$(1)),$(1),$(call cc-all-opts,$(1)))

# Below we verify that the compiler supports any -Wno-something option to
# disable any warning, or if a special option is needed to achieve that. This
# will allow to get rid of testing when the compiler doesn't care. The result
# is made of two variables:
#  - cc-anywno that's non-empty if the compiler supports disabling anything
#  - cc-wnouwo that may contain an option needed to enable this behavior
# Gcc 4.x and above do not need any option but will still complain about unknown
# options if another warning or error happens, and as such they're not testable.
# Clang needs a special option -Wno-unknown-warning-option. Compilers not
# supporting this option will check all warnings individually.
cc-anywno := $(call cc-opt,-Wno-haproxy-warning)
cc-wnouwo := $(if $(cc-anywno),,$(call cc-opt,-Wno-unknown-warning-option))
cc-anywno := $(if $(cc-anywno)$(cc-wnouwo),1)

# Disable a warning when supported by the compiler. Don't put spaces around the
# warning! And don't use cc-opt which doesn't always report an error until
# another one is also returned. If "cc-anywno" is set, the compiler supports
# -Wno- followed by anything so we don't even need to start the compiler.
# Usage: CFLAGS += $(call cc-nowarn,warning). Eg: $(call cc-opt,format-truncation)
cc-nowarn = $(if $(cc-anywno),-Wno-$(1),$(shell set -e; if $(CC) -Werror -W$(1) -E -xc - -o /dev/null </dev/null >&0 2>/dev/null; then echo "-Wno-$(1)"; fi;))
