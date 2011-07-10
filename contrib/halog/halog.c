/*
 * haproxy log statistics reporter
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <eb32tree.h>
#include <eb64tree.h>
#include <ebistree.h>
#include <ebsttree.h>

#define SOURCE_FIELD 5
#define ACCEPT_FIELD 6
#define SERVER_FIELD 8
#define TIME_FIELD 9
#define STATUS_FIELD 10
#define TERM_CODES_FIELD 14
#define CONN_FIELD 15
#define METH_FIELD 17
#define URL_FIELD 18
#define MAXLINE 16384
#define QBITS 4

#define SEP(c) ((unsigned char)(c) <= ' ')
#define SKIP_CHAR(p,c) do { while (1) { int __c = (unsigned char)*p++; if (__c == c) break; if (__c <= ' ') { p--; break; } } } while (0)

/* [0] = err/date, [1] = req, [2] = conn, [3] = resp, [4] = data */
static struct eb_root timers[5] = {
	EB_ROOT_UNIQUE, EB_ROOT_UNIQUE, EB_ROOT_UNIQUE,
	EB_ROOT_UNIQUE, EB_ROOT_UNIQUE,
};

struct timer {
	struct eb32_node node;
	unsigned int count;
};

struct srv_st {
	unsigned int st_cnt[6]; /* 0xx to 5xx */
	unsigned int nb_ct, nb_rt, nb_ok;
	unsigned long long cum_ct, cum_rt;
	struct ebmb_node node;
	/* don't put anything else here, the server name will be there */
};

struct url_stat {
	union {
		struct ebpt_node url;
		struct eb64_node val;
	} node;
	char *url;
	unsigned long long total_time;    /* sum(all reqs' times) */
	unsigned long long total_time_ok; /* sum(all OK reqs' times) */
	unsigned int nb_err, nb_req;
};

#define FILT_COUNT_ONLY		0x01
#define FILT_INVERT		0x02
#define FILT_QUIET		0x04
#define FILT_ERRORS_ONLY	0x08
#define FILT_ACC_DELAY		0x10
#define FILT_ACC_COUNT		0x20
#define FILT_GRAPH_TIMERS	0x40
#define FILT_PERCENTILE		0x80
#define FILT_TIME_RESP         0x100

#define FILT_INVERT_ERRORS     0x200
#define FILT_INVERT_TIME_RESP  0x400

#define FILT_COUNT_STATUS      0x800
#define FILT_COUNT_SRV_STATUS 0x1000
#define FILT_COUNT_TERM_CODES 0x2000

#define FILT_COUNT_URL_ONLY  0x004000
#define FILT_COUNT_URL_COUNT 0x008000
#define FILT_COUNT_URL_ERR   0x010000
#define FILT_COUNT_URL_TTOT  0x020000
#define FILT_COUNT_URL_TAVG  0x040000
#define FILT_COUNT_URL_TTOTO 0x080000
#define FILT_COUNT_URL_TAVGO 0x100000
#define FILT_COUNT_URL_ANY   (FILT_COUNT_URL_ONLY|FILT_COUNT_URL_COUNT|FILT_COUNT_URL_ERR| \
			      FILT_COUNT_URL_TTOT|FILT_COUNT_URL_TAVG|FILT_COUNT_URL_TTOTO|FILT_COUNT_URL_TAVGO)

#define FILT_HTTP_ONLY       0x200000

unsigned int filter = 0;
unsigned int filter_invert = 0;
const char *line;

const char *fgets2(FILE *stream);

void die(const char *msg)
{
	fprintf(stderr,
		"%s"
		"Usage: halog [-q] [-c] [-v] {-gt|-pct|-st|-tc|-srv|-u|-uc|-ue|-ua|-ut|-uao|-uto}\n"
		"       [-s <skip>] [-e|-E] [-H] [-rt|-RT <time>] [-ad <delay>] [-ac <count>] < log\n"
		"\n",
		msg ? msg : ""
		);
	exit(1);
}


/* return pointer to first char not part of current field starting at <p>. */
const char *field_stop(const char *p)
{
	unsigned char c;

	while (1) {
		c = *(p++);
		if (c > ' ')
			continue;
		if (c == ' ' || c == '\t' || c == 0)
			break;
	}
	return p - 1;
}

/* return field <field> (starting from 1) in string <p>. Only consider
 * contiguous spaces (or tabs) as one delimiter. May return pointer to
 * last char if field is not found. Equivalent to awk '{print $field}'.
 */
const char *field_start(const char *p, int field)
{
	unsigned char c;
	while (1) {
		/* skip spaces */
		while (1) {
			c = *p;
			if (c > ' ')
				break;
			if (c == ' ' || c == '\t')
				goto next;
			if (!c) /* end of line */
				return p;
			/* other char => new field */
			break;
		next:
			p++;
		}

		/* start of field */
		field--;
		if (!field)
			return p;

		/* skip this field */
		while (1) {
			c = *(p++);
			if (c > ' ')
				continue;
			if (c == ' ' || c == '\t')
				break;
			if (c == '\0')
				return p;
		}
	}
}

/* keep only the <bits> higher bits of <i> */
static inline unsigned int quantify_u32(unsigned int i, int bits)
{
	int high;

	if (!bits)
		return 0;

	if (i)
		high = fls_auto(i);    // 1 to 32
	else
		high = 0;

	if (high <= bits)
		return i;

	return i & ~((1 << (high - bits)) - 1);
}

/* keep only the <bits> higher bits of the absolute value of <i>, as well as
 * its sign. */
static inline int quantify(int i, int bits)
{
	if (i >= 0)
		return quantify_u32(i, bits);
	else
		return -quantify_u32(-i, bits);
}

/* Insert timer value <v> into tree <r>. A pre-allocated node must be passed
 * in <alloc>. It may be NULL, in which case the function will allocate it
 * itself. It will be reset to NULL once consumed. The caller is responsible
 * for freeing the node once not used anymore. The node where the value was
 * inserted is returned.
 */
struct timer *insert_timer(struct eb_root *r, struct timer **alloc, int v)
{
	struct timer *t = *alloc;
	struct eb32_node *n;

	if (!t) {
		t = calloc(sizeof(*t), 1);
		if (unlikely(!t)) {
			fprintf(stderr, "%s: not enough memory\n", __FUNCTION__);
			exit(1);
		}
	}
	t->node.key = quantify(v, QBITS);         // keep only the higher QBITS bits

	n = eb32i_insert(r, &t->node);
	if (n == &t->node)
		t = NULL;  /* node inserted, will malloc next time */

	*alloc = t;
	return container_of(n, struct timer, node);
}

/* Insert value value <v> into tree <r>. A pre-allocated node must be passed
 * in <alloc>. It may be NULL, in which case the function will allocate it
 * itself. It will be reset to NULL once consumed. The caller is responsible
 * for freeing the node once not used anymore. The node where the value was
 * inserted is returned.
 */
struct timer *insert_value(struct eb_root *r, struct timer **alloc, int v)
{
	struct timer *t = *alloc;
	struct eb32_node *n;

	if (!t) {
		t = calloc(sizeof(*t), 1);
		if (unlikely(!t)) {
			fprintf(stderr, "%s: not enough memory\n", __FUNCTION__);
			exit(1);
		}
	}
	t->node.key = v;

	n = eb32i_insert(r, &t->node);
	if (n == &t->node)
		t = NULL;  /* node inserted, will malloc next time */

	*alloc = t;
	return container_of(n, struct timer, node);
}

int str2ic(const char *s)
{
	int i = 0;
	int j, k;

	if (*s != '-') {
		/* positive number */
		while (1) {
			j = (*s++) - '0';
			k = i * 10;
			if ((unsigned)j > 9)
				break;
			i = k + j;
		}
	} else {
		/* negative number */
		s++;
		while (1) {
			j = (*s++) - '0';
			k = i * 10;
			if ((unsigned)j > 9)
				break;
			i = k - j;
		}
	}

	return i;
}


/* Equivalent to strtoul with a length. */
static inline unsigned int __strl2ui(const char *s, int len)
{
	unsigned int i = 0;
	while (len-- > 0) {
		i = i * 10 - '0';
		i += (unsigned char)*s++;
	}
	return i;
}

unsigned int strl2ui(const char *s, int len)
{
	return __strl2ui(s, len);
}

/* Convert "[04/Dec/2008:09:49:40.555]" to an integer equivalent to the time of
 * the day in milliseconds. It returns -1 for all unparsable values. The parser
 * looks ugly but gcc emits far better code that way.
 */
int convert_date(const char *field)
{
	unsigned int h, m, s, ms;
	unsigned char c;
	const char *b, *e;

	h = m = s = ms = 0;
	e = field;

	/* skip the date */
	while (1) {
		c = *(e++);
		if (c == ':')
			break;
		if (!c)
			goto out_err;
	}

	/* hour + ':' */
	b = e;
	while (1) {
		c = *(e++) - '0';
		if (c > 9)
			break;
		h = h * 10 + c;
	}
	if (c == (unsigned char)(0 - '0'))
		goto out_err;

	/* minute + ':' */
	b = e;
	while (1) {
		c = *(e++) - '0';
		if (c > 9)
			break;
		m = m * 10 + c;
	}
	if (c == (unsigned char)(0 - '0'))
		goto out_err;

	/* second + '.' or ']' */
	b = e;
	while (1) {
		c = *(e++) - '0';
		if (c > 9)
			break;
		s = s * 10 + c;
	}
	if (c == (unsigned char)(0 - '0'))
		goto out_err;

	/* if there's a '.', we have milliseconds */
	if (c == (unsigned char)('.' - '0')) {
		/* millisecond second + ']' */
		b = e;
		while (1) {
			c = *(e++) - '0';
			if (c > 9)
				break;
			ms = ms * 10 + c;
		}
		if (c == (unsigned char)(0 - '0'))
			goto out_err;
	}
	return (((h * 60) + m) * 60 + s) * 1000 + ms;
 out_err:
	return -1;
}

void truncated_line(int linenum, const char *line)
{
	if (!(filter & FILT_QUIET))
		fprintf(stderr, "Truncated line %d: %s\n", linenum, line);
}

int main(int argc, char **argv)
{
	const char *b, *e, *p;
	const char *output_file = NULL;
	int f, tot, last, linenum, err, parse_err;
	struct timer *t = NULL, *t2;
	struct eb32_node *n;
	struct url_stat *ustat = NULL;
	struct ebpt_node *ebpt_old;
	int val, test;
	int array[5];
	int filter_acc_delay = 0, filter_acc_count = 0;
	int filter_time_resp = 0;
	int skip_fields = 1;

	argc--; argv++;
	while (argc > 0) {
		if (*argv[0] != '-')
			break;

		if (strcmp(argv[0], "-ad") == 0) {
			if (argc < 2) die("missing option for -ad");
			argc--; argv++;
			filter |= FILT_ACC_DELAY;
			filter_acc_delay = atol(*argv);
		}
		else if (strcmp(argv[0], "-ac") == 0) {
			if (argc < 2) die("missing option for -ac");
			argc--; argv++;
			filter |= FILT_ACC_COUNT;
			filter_acc_count = atol(*argv);
		}
		else if (strcmp(argv[0], "-rt") == 0) {
			if (argc < 2) die("missing option for -rt");
			argc--; argv++;
			filter |= FILT_TIME_RESP;
			filter_time_resp = atol(*argv);
		}
		else if (strcmp(argv[0], "-RT") == 0) {
			if (argc < 2) die("missing option for -RT");
			argc--; argv++;
			filter |= FILT_TIME_RESP | FILT_INVERT_TIME_RESP;
			filter_time_resp = atol(*argv);
		}
		else if (strcmp(argv[0], "-s") == 0) {
			if (argc < 2) die("missing option for -s");
			argc--; argv++;
			skip_fields = atol(*argv);
		}
		else if (strcmp(argv[0], "-e") == 0)
			filter |= FILT_ERRORS_ONLY;
		else if (strcmp(argv[0], "-E") == 0)
			filter |= FILT_ERRORS_ONLY | FILT_INVERT_ERRORS;
		else if (strcmp(argv[0], "-H") == 0)
			filter |= FILT_HTTP_ONLY;
		else if (strcmp(argv[0], "-c") == 0)
			filter |= FILT_COUNT_ONLY;
		else if (strcmp(argv[0], "-q") == 0)
			filter |= FILT_QUIET;
		else if (strcmp(argv[0], "-v") == 0)
			filter_invert = !filter_invert;
		else if (strcmp(argv[0], "-gt") == 0)
			filter |= FILT_GRAPH_TIMERS;
		else if (strcmp(argv[0], "-pct") == 0)
			filter |= FILT_PERCENTILE;
		else if (strcmp(argv[0], "-st") == 0)
			filter |= FILT_COUNT_STATUS;
		else if (strcmp(argv[0], "-srv") == 0)
			filter |= FILT_COUNT_SRV_STATUS;
		else if (strcmp(argv[0], "-tc") == 0)
			filter |= FILT_COUNT_TERM_CODES;
		else if (strcmp(argv[0], "-u") == 0)
			filter |= FILT_COUNT_URL_ONLY;
		else if (strcmp(argv[0], "-uc") == 0)
			filter |= FILT_COUNT_URL_COUNT;
		else if (strcmp(argv[0], "-ue") == 0)
			filter |= FILT_COUNT_URL_ERR;
		else if (strcmp(argv[0], "-ua") == 0)
			filter |= FILT_COUNT_URL_TAVG;
		else if (strcmp(argv[0], "-ut") == 0)
			filter |= FILT_COUNT_URL_TTOT;
		else if (strcmp(argv[0], "-uao") == 0)
			filter |= FILT_COUNT_URL_TAVGO;
		else if (strcmp(argv[0], "-uto") == 0)
			filter |= FILT_COUNT_URL_TTOTO;
		else if (strcmp(argv[0], "-o") == 0) {
			if (output_file)
				die("Fatal: output file name already specified.\n");
			if (argc < 2)
				die("Fatal: missing output file name.\n");
			output_file = argv[1];
		}
		argc--;
		argv++;
	}

	if (!filter)
		die("No action specified.\n");

	if (filter & FILT_ACC_COUNT && !filter_acc_count)
		filter_acc_count=1;

	if (filter & FILT_ACC_DELAY && !filter_acc_delay)
		filter_acc_delay = 1;

	linenum = 0;
	tot = 0;
	parse_err = 0;

	while ((line = fgets2(stdin)) != NULL) {
		linenum++;

		test = 1;
		if (unlikely(filter & FILT_HTTP_ONLY)) {
			/* only report lines with at least 4 timers */
			b = field_start(line, TIME_FIELD + skip_fields);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			e = field_stop(b + 1);
			/* we have field TIME_FIELD in [b]..[e-1] */

			p = b;
			err = 0;
			f = 0;
			while (!SEP(*p)) {
				if (++f == 4)
					break;
				SKIP_CHAR(p, '/');
			}
			test &= (f >= 4);
		}

		if (unlikely(filter & FILT_TIME_RESP)) {
			int tps;

			/* only report lines with response times larger than filter_time_resp */
			b = field_start(line, TIME_FIELD + skip_fields);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			e = field_stop(b + 1);
			/* we have field TIME_FIELD in [b]..[e-1], let's check only the response time */

			p = b;
			err = 0;
			f = 0;
			while (!SEP(*p)) {
				tps = str2ic(p);
				if (tps < 0) {
					tps = -1;
					err = 1;
				}
				if (++f == 4)
					break;
				SKIP_CHAR(p, '/');
			}

			if (f < 4) {
				parse_err++;
				continue;
			}

			test &= (tps >= filter_time_resp) ^ !!(filter & FILT_INVERT_TIME_RESP);
		}

		if (unlikely(filter & FILT_ERRORS_ONLY)) {
			/* only report erroneous status codes */
			b = field_start(line, STATUS_FIELD + skip_fields);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}
			if (*b == '-') {
				test &= !!(filter & FILT_INVERT_ERRORS);
			} else {
				val = strl2ui(b, 3);
				test &= (val >= 500 && val <= 599) ^ !!(filter & FILT_INVERT_ERRORS);
			}
		}

		test ^= filter_invert;
		if (!test)
			continue;

		if (unlikely(filter & (FILT_ACC_COUNT|FILT_ACC_DELAY))) {
			b = field_start(line, ACCEPT_FIELD + skip_fields);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			tot++;
			val = convert_date(b);
			//printf("date=%s => %d\n", b, val);
			if (val < 0) {
				parse_err++;
				continue;
			}

			t2 = insert_value(&timers[0], &t, val);
			t2->count++;
			continue;
		}

		if (unlikely(filter & (FILT_GRAPH_TIMERS|FILT_PERCENTILE))) {
			int f;

			b = field_start(line, TIME_FIELD + skip_fields);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			e = field_stop(b + 1);
			/* we have field TIME_FIELD in [b]..[e-1] */

			p = b;
			err = 0;
			f = 0;
			while (!SEP(*p)) {
				array[f] = str2ic(p);
				if (array[f] < 0) {
					array[f] = -1;
					err = 1;
				}
				if (++f == 5)
					break;
				SKIP_CHAR(p, '/');
			}

			if (f < 5) {
				parse_err++;
				continue;
			}

			/* if we find at least one negative time, we count one error
			 * with a time equal to the total session time. This will
			 * emphasize quantum timing effects associated to known
			 * timeouts. Note that on some buggy machines, it is possible
			 * that the total time is negative, hence the reason to reset
			 * it.
			 */

			if (filter & FILT_GRAPH_TIMERS) {
				if (err) {
					if (array[4] < 0)
						array[4] = -1;
					t2 = insert_timer(&timers[0], &t, array[4]);  // total time
					t2->count++;
				} else {
					int v;

					t2 = insert_timer(&timers[1], &t, array[0]); t2->count++;  // req
					t2 = insert_timer(&timers[2], &t, array[2]); t2->count++;  // conn
					t2 = insert_timer(&timers[3], &t, array[3]); t2->count++;  // resp

					v = array[4] - array[0] - array[1] - array[2] - array[3]; // data time
					if (v < 0 && !(filter & FILT_QUIET))
						fprintf(stderr, "ERR: %s (%d %d %d %d %d => %d)\n",
							line, array[0], array[1], array[2], array[3], array[4], v);
					t2 = insert_timer(&timers[4], &t, v); t2->count++;
					tot++;
				}
			} else { /* percentile */
				if (err) {
					if (array[4] < 0)
						array[4] = -1;
					t2 = insert_value(&timers[0], &t, array[4]);  // total time
					t2->count++;
				} else {
					int v;

					t2 = insert_value(&timers[1], &t, array[0]); t2->count++;  // req
					t2 = insert_value(&timers[2], &t, array[2]); t2->count++;  // conn
					t2 = insert_value(&timers[3], &t, array[3]); t2->count++;  // resp

					v = array[4] - array[0] - array[1] - array[2] - array[3]; // data time
					if (v < 0 && !(filter & FILT_QUIET))
						fprintf(stderr, "ERR: %s (%d %d %d %d %d => %d)\n",
							line, array[0], array[1], array[2], array[3], array[4], v);
					t2 = insert_value(&timers[4], &t, v); t2->count++;
					tot++;
				}
			}
			continue;
		}

		if (unlikely(filter & FILT_COUNT_STATUS)) {
			/* first, let's ensure that the line is a traffic line (beginning
			 * with an IP address)
			 */
			b = field_start(line, SOURCE_FIELD + skip_fields);
			if (*b < '0' || *b > '9') {
				parse_err++;
				continue;
			}

			b = field_start(b, STATUS_FIELD - SOURCE_FIELD + 1);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}
			val = str2ic(b);

			t2 = insert_value(&timers[0], &t, val);
			t2->count++;
			continue;
		}

		if (unlikely(filter & FILT_COUNT_TERM_CODES)) {
			/* first, let's ensure that the line is a traffic line (beginning
			 * with an IP address)
			 */
			b = field_start(line, SOURCE_FIELD + skip_fields);
			if (*b < '0' || *b > '9') {
				parse_err++;
				continue;
			}

			b = field_start(b, TERM_CODES_FIELD - SOURCE_FIELD + 1);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}
			val = 256 * b[0] + b[1];

			t2 = insert_value(&timers[0], &t, val);
			t2->count++;
			continue;
		}

		if (unlikely(filter & FILT_COUNT_SRV_STATUS)) {
			char *srv_name;
			struct ebmb_node *srv_node;
			struct srv_st *srv;

			/* first, let's ensure that the line is a traffic line (beginning
			 * with an IP address)
			 */
			b = field_start(line, SOURCE_FIELD + skip_fields);
			if (*b < '0' || *b > '9') {
				parse_err++;
				continue;
			}

			/* the server field is before the status field, so let's
			 * parse them in the proper order.
			 */
			b = field_start(b, SERVER_FIELD - SOURCE_FIELD + 1);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			e = field_stop(b + 1);  /* we have the server name in [b]..[e-1] */

			/* the chance that a server name already exists is extremely high,
			 * so let's perform a normal lookup first.
			 */
			srv_node = ebst_lookup_len(&timers[0], b, e - b);
			srv = container_of(srv_node, struct srv_st, node);

			if (!srv_node) {
				/* server not yet in the tree, let's create it */
				srv = (void *)calloc(1, sizeof(struct srv_st) + e - b + 1);
				srv_node = &srv->node;
				memcpy(&srv_node->key, b, e - b);
				srv_node->key[e - b] = '\0';
				ebst_insert(&timers[0], srv_node);
			}

			/* let's collect the connect and response times */
			b = field_start(e, TIME_FIELD - SERVER_FIELD);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			e = field_stop(b + 1);
			/* we have field TIME_FIELD in [b]..[e-1] */

			p = b;
			err = 0;
			f = 0;
			while (!SEP(*p)) {
				array[f] = str2ic(p);
				if (array[f] < 0) {
					array[f] = -1;
					err = 1;
				}
				if (++f == 5)
					break;
				SKIP_CHAR(p, '/');
			}

			if (f < 5) {
				parse_err++;
				continue;
			}

			/* OK we have our timers in array[2,3] */
			if (!err)
				srv->nb_ok++;

			if (array[2] >= 0) {
				srv->cum_ct += array[2];
				srv->nb_ct++;
			}

			if (array[3] >= 0) {
				srv->cum_rt += array[3];
				srv->nb_rt++;
			}

			/* we're interested in the 5 HTTP status classes (1xx ... 5xx), and
			 * the invalid ones which will be reported as 0.
			 */
			b = field_start(e, STATUS_FIELD - TIME_FIELD);
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			val = 0;
			if (*b >= '1' && *b <= '5')
				val = *b - '0';

			srv->st_cnt[val]++;
			continue;
		}

		if (unlikely(filter & FILT_COUNT_URL_ANY)) {
			/* first, let's ensure that the line is a traffic line (beginning
			 * with an IP address)
			 */
			b = field_start(line, SOURCE_FIELD + skip_fields); // avg 95 ns per line
			if (*b < '0' || *b > '9') {
				parse_err++;
				continue;
			}

			/* let's collect the response time */
			b = field_start(field_stop(b + 1), TIME_FIELD - SOURCE_FIELD);  // avg 115 ns per line
			if (!*b) {
				truncated_line(linenum, line);
				continue;
			}

			/* we have the field TIME_FIELD starting at <b>. We'll
			 * parse the 5 timers to detect errors, it takes avg 55 ns per line.
			 */
			e = b; err = 0; f = 0;
			while (!SEP(*e)) {
				array[f] = str2ic(e);
				if (array[f] < 0) {
					array[f] = -1;
					err = 1;
				}
				if (++f == 5)
					break;
				SKIP_CHAR(e, '/');
			}
			if (f < 5) {
				parse_err++;
				continue;
			}

			/* OK we have our timers in array[3], and err is >0 if at
			 * least one -1 was seen. <e> points to the first char of
			 * the last timer. Let's prepare a new node with that.
			 */
			if (unlikely(!ustat))
				ustat = calloc(1, sizeof(*ustat));

			ustat->nb_err = err;
			ustat->nb_req = 1;

			/* use array[4] = total time in case of error */
			ustat->total_time = (array[3] >= 0) ? array[3] : array[4];
			ustat->total_time_ok = (array[3] >= 0) ? array[3] : 0;

			/* the line may be truncated because of a bad request or anything like this,
			 * without a method. Also, if it does not begin with an quote, let's skip to
			 * the next field because it's a capture. Let's fall back to the "method" itself
			 * if there's nothing else.
			 */
			e = field_start(e, METH_FIELD - TIME_FIELD + 1); // avg 100 ns per line
			while (*e != '"' && *e)
				e = field_start(e, 2);

			if (!*e) {
				truncated_line(linenum, line);
				continue;
			}

			b = field_start(e, URL_FIELD - METH_FIELD + 1); // avg 40 ns per line
			if (!*b)
				b = e;

			/* stop at end of field or first ';' or '?', takes avg 64 ns per line */
			e = b;
			do {
				if (*e == ' ' || *e == '?' || *e == ';' || *e == '\t') {
					*(char *)e = 0;
					break;
				}
				e++;
			} while (*e);

			/* now instead of copying the URL for a simple lookup, we'll link
			 * to it from the node we're trying to insert. If it returns a
			 * different value, it was already there. Otherwise we just have
			 * to dynamically realloc an entry using strdup().
			 */
			ustat->node.url.key = (char *)b;
			ebpt_old = ebis_insert(&timers[0], &ustat->node.url);

			if (ebpt_old != &ustat->node.url) {
				struct url_stat *ustat_old;
				/* node was already there, let's update previous one */
				ustat_old = container_of(ebpt_old, struct url_stat, node.url);
				ustat_old->nb_req ++;
				ustat_old->nb_err += ustat->nb_err;
				ustat_old->total_time += ustat->total_time;
				ustat_old->total_time_ok += ustat->total_time_ok;
			} else {
				ustat->url = ustat->node.url.key = strdup(ustat->node.url.key);
				ustat = NULL; /* node was used */
			}

			continue;
		}

		/* all other cases mean we just want to count lines */
		tot++;
		if (unlikely(!(filter & FILT_COUNT_ONLY)))
			puts(line);
	}

	if (t)
		free(t);

	if (filter & FILT_COUNT_ONLY) {
		printf("%d\n", tot);
		exit(0);
	}

	if (filter & (FILT_ACC_COUNT|FILT_ACC_DELAY)) {
		/* sort and count all timers. Output will look like this :
		 * <accept_date> <delta_ms from previous one> <nb entries>
		 */
		n = eb32_first(&timers[0]);

		if (n)
			last = n->key;
		while (n) {
			unsigned int d, h, m, s, ms;

			t = container_of(n, struct timer, node);
			h = n->key;
			d = h - last;
			last = h;

			if (d >= filter_acc_delay && t->count >= filter_acc_count) {
				ms = h % 1000; h = h / 1000;
				s = h % 60; h = h / 60;
				m = h % 60; h = h / 60;
				tot++;
				printf("%02d:%02d:%02d.%03d %d %d %d\n", h, m, s, ms, last, d, t->count);
			}
			n = eb32_next(n);
		}
	}
	else if (filter & FILT_GRAPH_TIMERS) {
		/* sort all timers */
		for (f = 0; f < 5; f++) {
			struct eb32_node *n;
			int val;

			val = 0;
			n = eb32_first(&timers[f]);
			while (n) {
				int i;
				double d;

				t = container_of(n, struct timer, node);
				last = n->key;
				val = t->count;

				i = (last < 0) ? -last : last;
				i = fls_auto(i) - QBITS;

				if (i > 0)
					d = val / (double)(1 << i);
				else
					d = val;

				if (d > 0.0) {
					printf("%d %d %f\n", f, last, d+1.0);
					tot++;
				}

				n = eb32_next(n);
			}
		}
	}
	else if (filter & FILT_PERCENTILE) {
		/* report timers by percentile :
		 *    <percent> <total> <max_req_time> <max_conn_time> <max_resp_time> <max_data_time>
		 * We don't count errs.
		 */
		struct eb32_node *n[5];
		unsigned long cum[5];
		double step;

		if (!tot)
			goto empty;

		for (f = 1; f < 5; f++) {
			n[f] = eb32_first(&timers[f]);
			cum[f] = container_of(n[f], struct timer, node)->count;
		}

		for (step = 1; step <= 1000;) {
			unsigned int thres = tot * (step / 1000.0);

			printf("%3.1f %d ", step/10.0, thres);
			for (f = 1; f < 5; f++) {
				struct eb32_node *next;
				while (cum[f] < thres) {
					/* need to find other keys */
					next = eb32_next(n[f]);
					if (!next)
						break;
					n[f] = next;
					cum[f] += container_of(next, struct timer, node)->count;
				}

				/* value still within $step % of total */
				printf("%d ", n[f]->key);
			}
			putchar('\n');
			if (step >= 100 && step < 900)
				step += 50;  // jump 5% by 5% between those steps.
			else if (step >= 20 && step < 980)
				step += 10;
			else
				step += 1;
		}
	}
	else if (filter & FILT_COUNT_STATUS) {
		/* output all statuses in the form of <status> <occurrences> */
		n = eb32_first(&timers[0]);
		while (n) {
			t = container_of(n, struct timer, node);
			printf("%d %d\n", n->key, t->count);
			n = eb32_next(n);
		}
	}
	else if (unlikely(filter & FILT_COUNT_SRV_STATUS)) {
		char *srv_name;
		struct ebmb_node *srv_node;
		struct srv_st *srv;

		printf("#srv_name 1xx 2xx 3xx 4xx 5xx other tot_req req_ok pct_ok avg_ct avg_rt\n");

		srv_node = ebmb_first(&timers[0]);
		while (srv_node) {
			int tot_rq;

			srv = container_of(srv_node, struct srv_st, node);

			tot_rq = 0;
			for (f = 0; f <= 5; f++)
				tot_rq += srv->st_cnt[f];

			printf("%s %d %d %d %d %d %d %d %d %.1f %d %d\n",
			       srv_node->key, srv->st_cnt[1], srv->st_cnt[2],
			       srv->st_cnt[3], srv->st_cnt[4], srv->st_cnt[5], srv->st_cnt[0],
			       tot_rq,
			       srv->nb_ok, (double)srv->nb_ok * 100.0 / (tot_rq?tot_rq:1),
			       (int)(srv->cum_ct / (srv->nb_ct?srv->nb_ct:1)), (int)(srv->cum_rt / (srv->nb_rt?srv->nb_rt:1)));
			srv_node = ebmb_next(srv_node);
			tot++;
		}
	}
	else if (filter & FILT_COUNT_TERM_CODES) {
		/* output all statuses in the form of <code> <occurrences> */
		n = eb32_first(&timers[0]);
		while (n) {
			t = container_of(n, struct timer, node);
			printf("%c%c %d\n", (n->key >> 8), (n->key) & 255, t->count);
			n = eb32_next(n);
		}
	}
	else if (unlikely(filter & FILT_COUNT_URL_ANY)) {
		char *srv_name;
		struct eb_node *node, *next;

		if (!(filter & FILT_COUNT_URL_ONLY)) {
			/* we have to sort on another criterion. We'll use timers[1] for the
			 * destination tree.
			 */

			timers[1] = EB_ROOT; /* reconfigure to accept duplicates */
			for (node = eb_first(&timers[0]); node; node = next) {
				next = eb_next(node);
				eb_delete(node);

				ustat = container_of(node, struct url_stat, node.url.node);

				if (filter & FILT_COUNT_URL_COUNT)
					ustat->node.val.key = ustat->nb_req;
				else if (filter & FILT_COUNT_URL_ERR)
					ustat->node.val.key = ustat->nb_err;
				else if (filter & FILT_COUNT_URL_TTOT)
					ustat->node.val.key = ustat->total_time;
				else if (filter & FILT_COUNT_URL_TAVG)
					ustat->node.val.key = ustat->nb_req ? ustat->total_time / ustat->nb_req : 0;
				else if (filter & FILT_COUNT_URL_TTOTO)
					ustat->node.val.key = ustat->total_time_ok;
				else if (filter & FILT_COUNT_URL_TAVGO)
					ustat->node.val.key = (ustat->nb_req - ustat->nb_err) ? ustat->total_time_ok / (ustat->nb_req - ustat->nb_err) : 0;
				else
					ustat->node.val.key = 0;

				eb64_insert(&timers[1], &ustat->node.val);
			}
			/* switch trees */
			timers[0] = timers[1];
		}

		printf("#req err ttot tavg oktot okavg url\n");

		/* scan the tree in its reverse sorting order */
		node = eb_last(&timers[0]);
		while (node) {
			ustat = container_of(node, struct url_stat, node.url.node);
			printf("%d %d %Ld %Ld %Ld %Ld %s\n",
			       ustat->nb_req,
			       ustat->nb_err,
			       ustat->total_time,
			       ustat->nb_req ? ustat->total_time / ustat->nb_req : 0,
			       ustat->total_time_ok,
			       (ustat->nb_req - ustat->nb_err) ? ustat->total_time_ok / (ustat->nb_req - ustat->nb_err) : 0,
			       ustat->url);

			node = eb_prev(node);
			tot++;
		}
	}

 empty:
	if (!(filter & FILT_QUIET))
		fprintf(stderr, "%d lines in, %d lines out, %d parsing errors\n",
			linenum, tot, parse_err);
	exit(0);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
