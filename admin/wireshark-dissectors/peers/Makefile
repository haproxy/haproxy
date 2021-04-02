CFLAGS  = `pkg-config --cflags wireshark` -g -fPIC $(OPTS)
LDFLAGS = `pkg-config --libs wireshark`

NAME = packet-happp.so
OBJS = packet-happp.o

plugins=$(HOME)/.wireshark/plugins/

$(NAME): $(OBJS)
	$(CC) -shared $(LDFLAGS) $(OBJS) -o $@

install: $(NAME)
	install -d $(DESTDIR)$(plugins)
	install -m 0755 $(NAME) $(DESTDIR)$(plugins)

clean:
	rm $(NAME) $(OBJS)
