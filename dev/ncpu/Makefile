include ../../include/make/verbose.mk

CC       = cc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = ncpu.so ncpu
OBJDUMP  = objdump

all:	$(OBJS)

%.o: %.c
	$(cmd_CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -shared -fPIC -c -o $@ $^

%.so: %.o
	$(cmd_CC) -pie -o $@ $^
	$(Q)rm -f $^

%: %.so
	$(call qinfo, PATCHING)set -- $$($(OBJDUMP) -j .dynamic -h $^ | fgrep .dynamic); \
	  ofs=$$6; size=$$3; \
	  dd status=none bs=1 count=$$((0x$$ofs)) if=$^ of=$^-p1; \
	  dd status=none bs=1 skip=$$((0x$$ofs)) count=$$((0x$$size)) if=$^ of=$^-p2; \
	  dd status=none bs=1 skip=$$((0x$$ofs+0x$$size)) if=$^ of=$^-p3; \
	  sed -e 's,\xfb\xff\xff\x6f\x00\x00\x00\x00\x00\x00\x00\x08,\xfb\xff\xff\x6f\x00\x00\x00\x00\x00\x00\x00\x00,g' < $^-p2 > $^-p2-patched; \
	  cat $^-p1 $^-p2-patched $^-p3 > "$@"
	$(Q)rm -f $^-p*
	$(Q)chmod 755 "$@"

clean:
	rm -f $(OBJS) *.[oas] *.so-* *~
