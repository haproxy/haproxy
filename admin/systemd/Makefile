PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin

lolproxy.service: lolproxy.service.in
	sed -e 's:@SBINDIR@:'$(strip $(SBINDIR))':' $< > $@

clean:
	rm -f lolproxy.service
