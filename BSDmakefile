# Makefile stub for FreeBSD, it checks BSDmakefile before Makefile so
# we can be friendly to the user and tell them to use gmake.
.BEGIN:
	@echo "Please use GNU make instead. It is often called gmake on BSD systems."
	@echo "Example:"
	@echo '  gmake ${MAKEFLAGS} $(.TARGETS)' | sed -e 's, -J[ ]*[0-9,]*,,'
	@echo

all $(.TARGETS): .SILENT
	@-
