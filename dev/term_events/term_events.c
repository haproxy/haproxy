#include <stdio.h>
#include <stdlib.h>

#include <haproxy/connection-t.h>
#include <haproxy/intops.h>

struct tevt_info {
	const char *loc;
	const char **types;
};


/* will be sufficient for even largest flag names */
static char buf[4096];
static size_t bsz = sizeof(buf);


static const char *tevt_unknown_types[16] = {
	[ 0] = "-", [ 1] = "-", [ 2] = "-", [ 3] = "-",
	[ 4] = "-", [ 5] = "-", [ 6] = "-", [ 7] = "-",
	[ 8] = "-", [ 9] = "-", [10] = "-", [11] = "-",
	[12] = "-", [13] = "-", [14] = "-", [15] = "-",
};

static const char *tevt_fd_types[16] = {
	[ 0] = "-",           [ 1] = "shutw",         [ 2] = "shutr",    [ 3] = "rcv_err",
	[ 4] = "snd_err",     [ 5] = "-",             [ 6] = "-",        [ 7] = "conn_err",
	[ 8] = "intercepted", [ 9] = "conn_poll_err", [10] = "poll_err", [11] = "poll_hup",
	[12] = "-",           [13] = "-",             [14] = "-",        [15] = "-",
};

static const char *tevt_hs_types[16] = {
	[ 0] = "-",       [ 1] = "-", [ 2] = "-", [ 3] = "rcv_err",
	[ 4] = "snd_err", [ 5] = "-", [ 6] = "-", [ 7] = "-",
	[ 8] = "-",       [ 9] = "-", [10] = "-", [11] = "-",
	[12] = "-",       [13] = "-", [14] = "-", [15] = "-",
};

static const char *tevt_xprt_types[16] = {
	[ 0] = "-",       [ 1] = "shutw", [ 2] = "shutr", [ 3] = "rcv_err",
	[ 4] = "snd_err", [ 5] = "-",     [ 6] = "-",     [ 7] = "-",
	[ 8] = "-",       [ 9] = "-",     [10] = "-",     [11] = "-",
	[12] = "-",       [13] = "-",     [14] = "-",     [15] = "-",
};

static const char *tevt_muxc_types[16] = {
	[ 0] = "-",             [ 1] = "shutw",           [ 2] = "shutr",             [ 3] = "rcv_err",
	[ 4] = "snd_err",       [ 5] = "truncated_shutr", [ 6] = "truncated_rcv_err", [ 7] = "tout",
	[ 8] = "goaway_rcvd",   [ 9] = "proto_err",       [10] = "internal_err",      [11] = "other_err",
	[12] = "graceful_shut", [13] = "-",               [14] = "-",                 [15] = "-",
};

static const char *tevt_se_types[16] = {
	[ 0] = "-",         [ 1] = "shutw",         [ 2] = "eos",               [ 3] = "rcv_err",
	[ 4] = "snd_err",   [ 5] = "truncated_eos", [ 6] = "truncated_rcv_err", [ 7] = "-",
	[ 8] = "rst_rcvd",  [ 9] = "proto_err",     [10] = "internal_err",      [11] = "other_err",
	[12] = "cancelled", [13] = "-",             [14] = "-",                 [15] = "-",
};

static const char *tevt_strm_types[16] = {
	[ 0] = "-",           [ 1] = "shutw",         [ 2] = "eos",               [ 3] = "rcv_err",
	[ 4] = "snd_err",     [ 5] = "truncated_eos", [ 6] = "truncated_rcv_err", [ 7] = "tout",
	[ 8] = "intercepted", [ 9] = "proto_err",     [10] = "internal_err",      [11] = "other_err",
	[12] = "aborted",     [13] = "-",             [14] = "-",                 [15] = "-",
};

static const struct tevt_info tevt_location[26] = {
	[ 0] = {.loc = "-",    .types = tevt_unknown_types}, [ 1] = {.loc = "-",    .types = tevt_unknown_types},
	[ 2] = {.loc = "-",    .types = tevt_unknown_types}, [ 3] = {.loc = "-",    .types = tevt_unknown_types},
	[ 4] = {.loc = "se",   .types = tevt_se_types},      [ 5] = {.loc = "fd",   .types = tevt_fd_types},
	[ 6] = {.loc = "-",    .types = tevt_unknown_types}, [ 7] = {.loc = "hs",   .types = tevt_hs_types},
	[ 8] = {.loc = "-",    .types = tevt_unknown_types}, [ 9] = {.loc = "-",    .types = tevt_unknown_types},
	[10] = {.loc = "-",    .types = tevt_unknown_types}, [11] = {.loc = "-",    .types = tevt_unknown_types},
	[12] = {.loc = "muxc", .types = tevt_muxc_types},    [13] = {.loc = "-",    .types = tevt_unknown_types},
	[14] = {.loc = "-",    .types = tevt_unknown_types}, [15] = {.loc = "-",    .types = tevt_unknown_types},
	[16] = {.loc = "-",    .types = tevt_unknown_types}, [17] = {.loc = "-",    .types = tevt_unknown_types},
	[18] = {.loc = "strm", .types = tevt_strm_types},    [19] = {.loc = "-",    .types = tevt_unknown_types},
	[20] = {.loc = "-",    .types = tevt_unknown_types}, [21] = {.loc = "-",    .types = tevt_unknown_types},
	[22] = {.loc = "-",    .types = tevt_unknown_types}, [23] = {.loc = "xprt", .types = tevt_xprt_types},
	[24] = {.loc = "-",    .types = tevt_unknown_types}, [25] = {.loc = "-",    .types = tevt_unknown_types},
};

void usage_exit(const char *name)
{
	fprintf(stderr, "Usage: %s { value* | - }\n", name);
	exit(1);
}

char *to_upper(char *dst, const char *src)
{
	int i;

	for (i = 0; src[i]; i++)
		dst[i] = toupper(src[i]);
	dst[i] = 0;
	return dst;
}

char *tevt_show_events(char *buf, size_t len, const char *delim, const char *value)
{
	char loc[5];
	int ret;

	if (!value || !*value) {
		snprintf(buf, len, "##NONE");
		goto end;
	}
	if (strcmp(value, "-") == 0) {
		snprintf(buf, len, "##UNK");
		goto end;
	}

	if (strlen(value) % 2 != 0) {
		snprintf(buf, len, "##INV");
		goto end;
	}

	while (*value) {
		struct tevt_info info;
		char l = value[0];
		char t = value[1];

		if (!isalpha(l) || !isxdigit(t)) {
			snprintf(buf, len, "##INV");
			goto end;
		}

		info = tevt_location[tolower(l) - 'a'];
		ret = snprintf(buf, len, "%s:%s%s",
			       isupper(l) ? to_upper(loc, info.loc) : info.loc,
			       info.types[hex2i(t)],
			       value[2] != 0 ? delim : "");
		if (ret < 0)
			break;
		len -= ret;
		buf += ret;
		value += 2;
	}

  end:
	return buf;
}

char *tevt_show_tuple_events(char *buf, size_t len, char *value)
{
	char *p = value;

	/* skip '{' */
	p++;
	while (*p) {
		char *v;
		char c;

		while (*p == ' ' || *p == '\t')
			p++;

		v = p;
		while (*p && *p != ',' && *p != '}')
			p++;
		c = *p;
		*p = 0;

		tevt_show_events(buf, len, " > ", v);
		printf("\t- %s\n", buf);

		*p = c;
		if (*p == ',')
			p++;
		else if (*p == '}')
			break;
		else {
			printf("\t- ##INV\n");
			break;
		}
	}

	*buf = 0;
	return buf;
}

int main(int argc, char **argv)
{
	const char *name = argv[0];
	char line[128];
	char *value;
	int multi = 0;
	int use_stdin = 0;
	char *err;

	while (argc == 1)
		usage_exit(name);

	argv++; argc--;
	if (argc > 1)
		multi = 1;

	if (strcmp(argv[0], "-") == 0)
		use_stdin = 1;

	while (argc > 0) {
		if (use_stdin) {
			value = fgets(line, sizeof(line), stdin);
			if (!value)
				break;

			/* skip common leading delimiters that slip from copy-paste */
			while (*value == ' ' || *value == '\t' || *value == ':' || *value == '=')
				value++;

			err = value;
			while (*err && *err != '\n')
				err++;
			*err = 0;
		}
		else {
			value = argv[0];
			argv++; argc--;
		}

		if (multi)
			printf("### %-8s : ", value);

		if (*value == '{') {
			if (!use_stdin)
				printf("\n");
			tevt_show_tuple_events(buf, bsz, value);
		}
		else
			tevt_show_events(buf, bsz, " > ", value);
		printf("%s\n", buf);
	}
	return 0;
}
