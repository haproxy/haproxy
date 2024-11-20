# error handling: define a "complain" function that maps either to "warning" or
# "error" depending on the "ERR" variable. The callers must use:
#  $(call $(complain),<msg>)

ifneq ($(ERR:0=),)
complain = error
else
complain = warning
endif
