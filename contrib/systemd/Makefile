PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin

haproxy.service: haproxy.service.in
	sed -e 's:@SBINDIR@:'$(strip $(SBINDIR))':' $< > $@

clean:
	rm -f haproxy.service
