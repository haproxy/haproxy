INCLUDE  = -I../../include

CC       = gcc
OPTIMIZE = -O2
DEFINE   =
OBJS     = flags poll

all: $(OBJS)

flags: flags.c
	$(CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

poll: poll.c
	$(CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
