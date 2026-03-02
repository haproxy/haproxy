#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <haproxy/hbuf.h>

__attribute__ ((format(printf, 2, 3)))
void hbuf_appendf(struct hbuf *h, char *fmt, ...)
{
	va_list argp;
	size_t room;
	int ret;

	room = h->size - h->data;
	if (!room)
		return;

	va_start(argp, fmt);
	ret = vsnprintf(h->area + h->data, room, fmt, argp);
	if (ret >= room)
		h->area[h->data] = '\0';
	else
		h->data += ret;
	va_end(argp);
}

/* Simple function, to append <line> to <b> without without
 * trailing '\0' character.
 * Take into an account the '\t' and '\n' escaped sequeces.
 */
void hbuf_str_append(struct hbuf *h, const char *line)
{
	const char *p, *end;
	char *to = h->area + h->data;
	char *wrap = h->area + h->size;
	int nl = 0; /* terminal '\n' */

	p = line;
	end = line + strlen(line);

	/* prepend '\t' if missing */
	if (strncmp(line, "\\t", 2) != 0 && to < wrap) {
		*to++ = '\t';
		h->data++;
	}

	while (p < end && to < wrap) {
		if (*p == '\\') {
			if (!*++p || p >= end)
				break;
			if (*p == 'n') {
				*to++ = '\n';
				if (p + 1 >= end)
					nl = 1;
			}
			else if (*p == 't')
				*to++ = '\t';
			p++;
			h->data++;
		}
		else {
			*to++ = *p++;
			h->data++;
		}
	}

	/* add a terminal '\n' if not already present */
	if (to < wrap && !nl) {
		*to++ = '\n';
		h->data++;
	}
}

