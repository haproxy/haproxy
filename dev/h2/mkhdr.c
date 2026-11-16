/*
 * Raw HTTP/2 frame generator. This is a C port of mkhdr.sh, which is much
 * faster when many frames need to be produced. The frames are emitted on
 * stdout.
 *
 * Usage: mkhdr <frame> [ [--] <frame> ]* > hdr.bin
 * See the usage message below for more options.
 *
 * Build like this from the top directory :
 *    make dev/h2/mkhdr
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char usage_msg[] =
	"Usage: %s <frame> [ [--] <frame> ]* > hdr.bin\n"
	"       %s -h | --help\n"
	"\n"
	"Each <frame> describes one frame (or series of frames) using the options\n"
	"below. \"--\" is used as an optional delimiter between such descriptions. They\n"
	"are processed independently from each other, and emitted in the same order.\n"
	"\n"
	"Options:\n"
	"  -t <type>          frame type, symbolic or numeric (default: DATA, or HEADERS\n"
	"                     when -e is used). Type \"p\" emits the connection preface.\n"
	"  -f <flags>[,...]   comma-delimited symbolic or numeric flags (default: 0)\n"
	"  -i <sid>[-<sid>]   stream ID, or range of stream IDs (default: 0). With a\n"
	"                     range, the frame(s) are emitted for each stream ID in\n"
	"                     ascending order, each of them <count> times (see -n).\n"
	"  -l <len>           value of the length field (default: payload length). With\n"
	"                     -d, maximum payload size of each frame (default: 16384).\n"
	"  -r <raw>           append raw data to the payload. Backslash escapes are\n"
	"                     interpreted (\\\\, \\n, \\r, \\t, \\xHH, \\NNN...).\n"
	"  -R <hex>           append hex codes to the payload. Blanks are ignored, and a\n"
	"                     leading 0 is implied for an odd number of digits.\n"
	"  -e <name> <value>  append a header field to the payload as a literal with\n"
	"                     incremental indexing. Escapes are interpreted as with -r.\n"
	"  -d <file>          take the payload from <file>, split into as many frames as\n"
	"                     needed. Cannot be combined with -r, -R or -e.\n"
	"  -n <count>         emit the resulting frame(s) <count> times in a row\n"
	"                     (default: 1).\n"
	"  -h, --help         show this help and exit.\n"
	"\n"
	"-r, -R and -e may be repeated and combined, the payload being made of their\n"
	"contents in their order of appearance. Numbers are decimal, 0xhex or 0octal.\n"
	"\n"
	"Supported symbolic types (case insensitive prefix match):\n"
	"   DATA        (0x00)      PUSH_PROMISE   (0x05)\n"
	"   HEADERS     (0x01)      PING           (0x06)\n"
	"   PRIORITY    (0x02)      GOAWAY         (0x07)\n"
	"   RST_STREAM  (0x03)      WINDOW_UPDATE  (0x08)\n"
	"   SETTINGS    (0x04)      CONTINUATION   (0x09)\n"
	"\n"
	"Supported symbolic flags (case insensitive prefix match):\n"
	"   ES          (0x01)      PAD            (0x08)\n"
	"   EH          (0x04)      PRIO           (0x20)\n"
	"   ACK         (0x01)\n"
	"\n";

/* stdout buffer. It must be provided as glibc ignores the size otherwise */
static char outbuf[65536];

static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* symbolic names, in the order they are checked for prefix matching */
static const struct { const char *name; int val; } types[] = {
	{ "DATA", 0x00 }, { "HEADERS", 0x01 }, { "RST_STREAM", 0x03 },
	{ "SETTINGS", 0x04 }, { "PING", 0x06 }, { "GOAWAY", 0x07 },
	{ "WINDOW_UPDATE", 0x08 }, { "CONTINUATION", 0x09 },
	{ "PRIORITY", 0x02 }, { "PUSH_PROMISE", 0x05 },
};

static const struct { const char *name; int val; } flag_names[] = {
	{ "ES", 0x01 }, { "EH", 0x04 }, { "PAD", 0x08 }, { "PRIO", 0x20 },
	{ "ACK", 0x01 },
};

/* options seen on the command line, to detect conflicts */
#define OPT_L  0x0001
#define OPT_T  0x0002
#define OPT_F  0x0004
#define OPT_I  0x0008
#define OPT_D  0x0010
#define OPT_N  0x0020
#define OPT_R  0x0040  /* -r or -R */
#define OPT_E  0x0080

/* a growable byte buffer */
struct bbuf {
	char *area;
	size_t len, size;
};

static const char *progname;

/* prints the usage message (to stderr on error) and exits with code <code> */
static void usage(int code)
{
	fprintf(code ? stderr : stdout, usage_msg, progname, progname);
	exit(code);
}

/* prints the message to stderr followed by the usage message, and exits
 * with code 1.
 */
__attribute__((noreturn, format(printf, 1, 2)))
static void fail(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fputc('\n', stderr);
	usage(1);
	exit(1);
}

/* appends <len> bytes from <data> to <b> */
static void bbuf_append(struct bbuf *b, const void *data, size_t len)
{
	if (b->len + len > b->size) {
		size_t new_size = b->size ? b->size : 256;

		while (new_size < b->len + len)
			new_size *= 2;
		b->area = realloc(b->area, new_size);
		if (!b->area) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
		b->size = new_size;
	}
	memcpy(b->area + b->len, data, len);
	b->len += len;
}

static void bbuf_putc(struct bbuf *b, unsigned char c)
{
	bbuf_append(b, &c, 1);
}

/* appends HPACK integer <v> with an <n>-bit prefix and <pfx> as the first
 * byte's high bits (RFC7541#5.1).
 */
static void bbuf_put_varint(struct bbuf *b, unsigned char pfx, int n, unsigned long v)
{
	unsigned long max = (1UL << n) - 1;

	if (v < max) {
		bbuf_putc(b, pfx | v);
		return;
	}
	bbuf_putc(b, pfx | max);
	v -= max;
	while (v >= 128) {
		bbuf_putc(b, 0x80 | (v & 127));
		v >>= 7;
	}
	bbuf_putc(b, v);
}

/* returns the value of hex digit <c>, or -1 if invalid */
static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* appends string <str> to <b> after interpreting printf-like backslash
 * escapes, and "%%" as "%".
 */
static void bbuf_put_unescaped(struct bbuf *b, const char *str)
{
	int c, i, v;

	while ((c = (unsigned char)*str++)) {
		if (c == '%' && *str == '%') {
			str++;
		}
		else if (c == '\\' && *str) {
			c = (unsigned char)*str++;
			switch (c) {
			case 'a': c = '\a'; break;
			case 'b': c = '\b'; break;
			case 'e': c = 0x1b; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'v': c = '\v'; break;
			case 'x':
				if (hexval(*str) < 0) {
					/* not an escape */
					bbuf_putc(b, '\\');
					break;
				}
				for (i = v = 0; i < 2 && hexval(*str) >= 0; i++)
					v = v * 16 + hexval(*str++);
				c = v;
				break;
			case '0' ... '7':
				v = c - '0';
				for (i = 1; i < 3 && *str >= '0' && *str <= '7'; i++)
					v = v * 8 + *str++ - '0';
				c = v & 255;
				break;
			case '\\':
			case '"':
			case '\'':
				break;
			default:
				/* unknown escape, keep it as-is */
				bbuf_putc(b, '\\');
				break;
			}
		}
		bbuf_putc(b, c);
	}
}

/* appends the binary form of hex string <hex> to <b>, ignoring blanks. If
 * the number of digits is odd, a leading zero is implied (e.g. "4" is 0x04).
 */
static void bbuf_put_hex(struct bbuf *b, const char *hex)
{
	const char *p;
	int hi = -1, v;
	int digits = 0;

	for (p = hex; *p; p++)
		digits += (*p != ' ' && *p != '\t');
	if (digits & 1)
		hi = 0;

	for (; *hex; hex++) {
		if (*hex == ' ' || *hex == '\t')
			continue;
		v = hexval(*hex);
		if (v < 0)
			fail("Invalid hex digit '%c' in raw hex data", *hex);
		if (hi < 0)
			hi = v;
		else {
			bbuf_putc(b, (hi << 4) | v);
			hi = -1;
		}
	}
}

/* parses number <str> (decimal, 0xhex or 0octal), and fails with <what> in
 * the error message if it cannot be parsed. Note that the number must start
 * with a digit.
 */
static unsigned long parse_num(const char *str, const char *what)
{
	unsigned long ret;
	char *end;

	if (!isdigit((unsigned char)*str))
		fail("Unparsable %s '%s'", what, str);
	errno = 0;
	ret = strtoul(str, &end, 0);
	if (errno || *end)
		fail("Unparsable %s '%s'", what, str);
	return ret;
}

/* parses stream ID or stream ID range <str> ("<first>[-<last>]") into
 * <first> and <last>. <last> equals <first> when no range is specified.
 */
static void parse_sid_range(const char *str, unsigned long *first, unsigned long *last)
{
	const char *dash = strchr(str, '-');
	char buf[64];

	if (!dash) {
		*first = *last = parse_num(str, "stream ID");
		return;
	}

	if (dash - str >= sizeof(buf))
		fail("Unparsable stream ID '%s'", str);
	memcpy(buf, str, dash - str);
	buf[dash - str] = 0;
	*first = parse_num(buf, "stream ID");
	*last = parse_num(dash + 1, "stream ID");
	if (*last < *first)
		fail("Invalid stream ID range '%s'", str);
}

/* parses frame type <str> and returns its value. Symbolic names are matched
 * by case-insensitive prefix, in the order of the types[] array.
 */
static int parse_type(const char *str)
{
	size_t len = strlen(str);
	int i;

	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		if (strncasecmp(types[i].name, str, len) == 0)
			return types[i].val;
	}
	if (isdigit((unsigned char)*str))
		return parse_num(str, "type");
	fail("Unknown type '%s'", str);
}

/* parses comma-delimited flags <str> and returns their combined value. Each
 * entry is either a symbolic name matched by case-insensitive prefix, or a
 * number.
 */
static int parse_flags(const char *str)
{
	char buf[64];
	const char *end;
	size_t len;
	int flags = 0;
	int i;

	while (*str) {
		end = strchr(str, ',');
		if (!end)
			end = str + strlen(str);
		len = end - str;
		if (len >= sizeof(buf))
			fail("Unknown flag(s) '%s'", str);
		memcpy(buf, str, len);
		buf[len] = 0;

		if (len) {
			for (i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
				if (strncasecmp(flag_names[i].name, buf, len) == 0)
					break;
			}

			if (i < sizeof(flag_names) / sizeof(flag_names[0]))
				flags |= flag_names[i].val;
			else if (isdigit((unsigned char)*buf))
				flags |= parse_num(buf, "flags");
			else
				fail("Unknown flag(s) '%s'", buf);
		}
		str = *end ? end + 1 : end;
	}
	return flags;
}

/* reads file <name> entirely into <b> */
static void read_file(struct bbuf *b, const char *name)
{
	char buf[65536];
	size_t got;
	FILE *f;

	f = fopen(name, "rb");
	if (!f) {
		fprintf(stderr, "Cannot open data file '%s': %s\n", name, strerror(errno));
		exit(1);
	}
	while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
		bbuf_append(b, buf, got);
	if (ferror(f)) {
		fprintf(stderr, "Error reading data file '%s'\n", name);
		exit(1);
	}
	fclose(f);
}

/* sets the stream ID of the frame starting at the beginning of <b> to <sid>.
 * If <all> is non-zero, all the frames that follow in <b> are updated as
 * well, which requires that their advertised lengths match their payload.
 */
static void set_sid(struct bbuf *b, unsigned long sid, int all)
{
	unsigned char *hdr;
	size_t ofs = 0;

	while (ofs + 9 <= b->len) {
		hdr = (unsigned char *)b->area + ofs;
		hdr[5] = (sid >> 24) & 0x7f;
		hdr[6] = sid >> 16;
		hdr[7] = sid >> 8;
		hdr[8] = sid;
		if (!all)
			break;
		ofs += 9 + ((hdr[0] << 16) | (hdr[1] << 8) | hdr[2]);
	}
}

/* appends a frame header made of <len>, <type>, <flags>, <sid> to <b> */
static void mkframe(struct bbuf *b, unsigned long len, int type, int flags, unsigned long sid)
{
	unsigned char hdr[9];

	hdr[0] = len >> 16;
	hdr[1] = len >> 8;
	hdr[2] = len;
	hdr[3] = type;
	hdr[4] = flags;
	hdr[5] = (sid >> 24) & 0x7f;
	hdr[6] = sid >> 16;
	hdr[7] = sid >> 8;
	hdr[8] = sid;
	bbuf_append(b, hdr, sizeof(hdr));
}

/* parses the <argc> options in <argv> describing one frame (or series of
 * frames), and emits it unless <check_only> is set. Exits on error.
 */
static void emit_frame(int argc, char **argv, int check_only)
{
	struct bbuf raw = { 0 };   /* payload (-r/-R/-e, in this order) */
	int has_hdrs = 0;          /* -e was used */
	struct bbuf data = { 0 };  /* data file contents (-d) */
	struct bbuf out = { 0 };   /* output for one stream */
	const char *data_file = NULL;
	const char *type_str = NULL;
	unsigned long len = 0, sid = 0, last_sid = 0;
	unsigned long count = 1;
	unsigned long n;
	int preface_only = 0;
	int seen = 0;
	int flags = 0;
	int type;

	if (argc <= 0)
		fail("Empty frame description");

	while (argc > 0 && **argv == '-') {
		const char *opt = *argv;
		int nargs = 1;
		int bit;

		if (strcmp(opt, "-h") == 0 || strcmp(opt, "--help") == 0)
			usage(0);
		else if (strcmp(opt, "-e") == 0)
			nargs = 2;
		else if (strcmp(opt, "-l") != 0 && strcmp(opt, "-t") != 0 &&
			 strcmp(opt, "-f") != 0 && strcmp(opt, "-i") != 0 &&
			 strcmp(opt, "-d") != 0 && strcmp(opt, "-r") != 0 &&
			 strcmp(opt, "-R") != 0 && strcmp(opt, "-n") != 0)
			fail("Unknown option '%s'", opt);

		if (argc <= nargs)
			fail("Missing argument for option '%s'", opt);

		/* all options but -e may only appear once */
		bit = opt[1] == 'l' ? OPT_L : opt[1] == 't' ? OPT_T :
		      opt[1] == 'f' ? OPT_F : opt[1] == 'i' ? OPT_I :
		      opt[1] == 'd' ? OPT_D : opt[1] == 'n' ? OPT_N :
		      opt[1] == 'e' ? OPT_E : OPT_R;
		if ((seen & bit) && bit != OPT_E && bit != OPT_R)
			fail("Option '%s' may only appear once", opt);
		seen |= bit;

		if (strcmp(opt, "-l") == 0)
			len = parse_num(argv[1], "length");
		else if (strcmp(opt, "-t") == 0)
			type_str = argv[1];
		else if (strcmp(opt, "-f") == 0)
			flags = parse_flags(argv[1]);
		else if (strcmp(opt, "-i") == 0)
			parse_sid_range(argv[1], &sid, &last_sid);
		else if (strcmp(opt, "-d") == 0)
			data_file = argv[1];
		else if (strcmp(opt, "-n") == 0)
			count = parse_num(argv[1], "count");
		else if (strcmp(opt, "-r") == 0)
			bbuf_put_unescaped(&raw, argv[1]);
		else if (strcmp(opt, "-R") == 0)
			bbuf_put_hex(&raw, argv[1]);
		else if (strcmp(opt, "-e") == 0) {
			/* literal header field with incremental indexing, new name */
			struct bbuf tmp = { 0 };

			has_hdrs = 1;
			bbuf_putc(&raw, 0x40);
			bbuf_put_unescaped(&tmp, argv[1]);
			bbuf_put_varint(&raw, 0, 7, tmp.len);
			bbuf_append(&raw, tmp.area, tmp.len);
			tmp.len = 0;
			bbuf_put_unescaped(&tmp, argv[2]);
			bbuf_put_varint(&raw, 0, 7, tmp.len);
			bbuf_append(&raw, tmp.area, tmp.len);
			free(tmp.area);
		}
		argv += nargs + 1;
		argc -= nargs + 1;
	}

	if (argc > 0)
		fail("Unexpected argument '%s'", *argv);

	/* reject options that would otherwise be silently ignored */
	if (type_str && strcmp(type_str, "p") == 0 && (seen & ~(OPT_T | OPT_N)))
		fail("The preface only supports -n");
	if ((seen & OPT_D) && (seen & (OPT_R | OPT_E)))
		fail("-d cannot be combined with -r, -R or -e");

	if (check_only) {
		if (type_str && strcmp(type_str, "p") != 0)
			parse_type(type_str);
		goto leave;
	}

	if (type_str && strcmp(type_str, "p") == 0) {
		bbuf_append(&out, preface, sizeof(preface) - 1);
		preface_only = 1;
	}
	else if (!data_file) {
		/* -e implies HEADERS unless a type was set */
		type = type_str ? parse_type(type_str) : has_hdrs ? 0x01 : 0x00;

		/* the length defaults to that of the payload */
		if (!(seen & OPT_L))
			len = raw.len;

		mkframe(&out, len, type, flags, sid);
		bbuf_append(&out, raw.area, raw.len);
	}
	else {
		/* read file <data_file> in <len> chunks and send it in multiple
		 * frames advertising their respective lengths.
		 */
		size_t ofs, chunk;

		type = type_str ? parse_type(type_str) : 0;
		read_file(&data, data_file);
		if (!len)
			len = 16384;

		for (ofs = 0; ofs < data.len; ofs += chunk) {
			chunk = data.len - ofs;
			if (chunk > len)
				chunk = len;
			mkframe(&out, chunk, type, flags, sid);
			bbuf_append(&out, data.area + ofs, chunk);
		}
	}

	/* emit the frame(s) <count> times for each stream ID of the range.
	 * The frames were built for the first one.
	 */
	while (out.len) {
		for (n = 0; n < count; n++) {
			if (fwrite(out.area, 1, out.len, stdout) != out.len) {
				fprintf(stderr, "Write error: %s\n", strerror(errno));
				exit(1);
			}
		}
		if (sid >= last_sid)
			break;
		sid++;
		if (!preface_only)
			set_sid(&out, sid, !!data_file);
	}

leave:
	free(raw.area);
	free(data.area);
	free(out.area);
}

int main(int argc, char **argv)
{
	int check_only, first, i;

	progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];

	/* use a large output buffer so that frames are not emitted in small
	 * chunks (stdio defaults to 4kB on pipes).
	 */
	setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));

	if (argc <= 1)
		usage(1);

	/* frame descriptions are delimited by "--". They are all checked
	 * first so that nothing is emitted if any of them is invalid.
	 */
	for (check_only = 1; check_only >= 0; check_only--) {
		for (first = i = 1; i <= argc; i++) {
			if (i < argc && strcmp(argv[i], "--") != 0)
				continue;
			emit_frame(i - first, argv + first, check_only);
			first = i + 1;
		}
	}

	if (fflush(stdout) != 0) {
		fprintf(stderr, "Write error: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}
