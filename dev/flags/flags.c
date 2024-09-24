#include <stdio.h>
#include <stdlib.h>

/* make the include files below expose their flags */
#define HA_EXPOSE_FLAGS

#include <haproxy/applet-t.h>
#include <haproxy/channel-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/fd-t.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/htx-t.h>
#include <haproxy/mux_fcgi-t.h>
#include <haproxy/mux_h2-t.h>
#include <haproxy/mux_h1-t.h>
#include <haproxy/mux_quic-t.h>
#include <haproxy/mux_spop-t.h>
#include <haproxy/peers-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/stconn-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/task-t.h>

// 1 bit per flag, no hole permitted here
#define SHOW_AS_ANA   0x00000001
#define SHOW_AS_CHN   0x00000002
#define SHOW_AS_CONN  0x00000004
#define SHOW_AS_SC    0x00000008
#define SHOW_AS_SET   0x00000010
#define SHOW_AS_STRM  0x00000020
#define SHOW_AS_TASK  0x00000040
#define SHOW_AS_TXN   0x00000080
#define SHOW_AS_SD    0x00000100
#define SHOW_AS_HSL   0x00000200
#define SHOW_AS_HTX   0x00000400
#define SHOW_AS_HMSG  0x00000800
#define SHOW_AS_FD    0x00001000
#define SHOW_AS_H2C   0x00002000
#define SHOW_AS_H2S   0x00004000
#define SHOW_AS_H1C   0x00008000
#define SHOW_AS_H1S   0x00010000
#define SHOW_AS_FCONN 0x00020000
#define SHOW_AS_FSTRM 0x00040000
#define SHOW_AS_PEERS 0x00080000
#define SHOW_AS_PEER  0x00100000
#define SHOW_AS_QC    0x00200000
#define SHOW_AS_SPOPC 0x00400000
#define SHOW_AS_SPOPS 0x00800000
#define SHOW_AS_QCC   0x01000000
#define SHOW_AS_QCS   0x02000000
#define SHOW_AS_APPCTX 0x04000000

// command line names, must be in exact same order as the SHOW_AS_* flags above
// so that show_as_words[i] matches flag 1U<<i.
const char *show_as_words[] = { "ana", "chn", "conn", "sc", "stet", "strm", "task", "txn", "sd", "hsl", "htx", "hmsg", "fd", "h2c", "h2s",  "h1c", "h1s", "fconn", "fstrm",
				"peers", "peer", "qc", "spopc", "spops", "qcc", "qcs", "appctx"};

/* will be sufficient for even largest flag names */
static char buf[4096];
static size_t bsz = sizeof(buf);

unsigned int get_show_as(const char *word)
{
	int w = 0;

	while (1) {
		if (w == sizeof(show_as_words) / sizeof(*show_as_words))
			return 0;
		if (strcmp(word, show_as_words[w]) == 0)
			return 1U << w;
		w++;
	}
}

void usage_exit(const char *name)
{
	int word, nbword;

	fprintf(stderr, "Usage: %s [", name);

	nbword = sizeof(show_as_words) / sizeof(*show_as_words);
	for (word = 0; word < nbword; word++)
		fprintf(stderr, "%s%s", word ? "|" : "", show_as_words[word]);
	fprintf(stderr, "]* { [+-][0x]value* | - }\n");
	exit(1);
}

int main(int argc, char **argv)
{
	unsigned int flags;
	unsigned int show_as = 0;
	unsigned int f;
	const char *name = argv[0];
	char line[20];
	char *value;
	int multi = 0;
	int use_stdin = 0;
	char *err;

	while (argc > 0) {
		argv++; argc--;
		if (argc < 1)
			usage_exit(name);

		f = get_show_as(argv[0]);
		if (!f)
			break;
		show_as |= f;
	}

	if (!show_as)
		show_as = ~0U;

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

			/* stop at the end of the number and trim any C suffix like "UL" */
			err = value;
			while (*err == '-' || *err == '+' ||
			       (isalnum((unsigned char)*err) && toupper((unsigned char)*err) != 'U' && toupper((unsigned char)*err) != 'L'))
				err++;
			*err = 0;
		} else {
			value = argv[0];
			argv++; argc--;
		}

		flags = strtoul(value, &err, 0);
		if (!*value || *err) {
			fprintf(stderr, "Unparsable value: <%s>\n", value);
			usage_exit(name);
		}

		if (multi || use_stdin)
			printf("### 0x%08x:\n", flags);

		if (show_as & SHOW_AS_ANA)   printf("chn->ana    = %s\n", (chn_show_analysers(buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_CHN)   printf("chn->flags  = %s\n", (chn_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_CONN)  printf("conn->flags = %s\n", (conn_show_flags   (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_SC)    printf("sc->flags = %s\n",   (sc_show_flags     (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_SD)    printf("sd->flags = %s\n",   (se_show_flags     (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_SET)   printf("strm->et = %s\n",    (strm_et_show_flags(buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_STRM)  printf("strm->flags = %s\n", (strm_show_flags   (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_TASK)  printf("task->state = %s\n", (task_show_state   (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_TXN)   printf("txn->flags = %s\n",  (txn_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_HSL)   printf("sl->flags = %s\n",   (hsl_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_HTX)   printf("htx->flags = %s\n",  (htx_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_HMSG)  printf("hmsg->flags = %s\n", (hmsg_show_flags   (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_FD)    printf("fd->flags = %s\n",   (fd_show_flags     (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_H2C)   printf("h2c->flags = %s\n",  (h2c_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_H2S)   printf("h2s->flags = %s\n",  (h2s_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_H1C)   printf("h1c->flags = %s\n",  (h1c_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_H1S)   printf("h1s->flags = %s\n",  (h1s_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_FCONN) printf("fconn->flags = %s\n",(fconn_show_flags  (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_FSTRM) printf("fstrm->flags = %s\n",(fstrm_show_flags  (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_PEERS) printf("peers->flags = %s\n",(peers_show_flags  (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_PEER)  printf("peer->flags = %s\n", (peer_show_flags   (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_QC)    printf("qc->flags = %s\n",   (qc_show_flags     (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_SPOPC) printf("spopc->flags = %s\n",(spop_conn_show_flags(buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_SPOPS) printf("spops->flags = %s\n",(spop_strm_show_flags(buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_QCC)    printf("qcc->flags = %s\n", (qcc_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_QCS)    printf("qcs->flags = %s\n", (qcs_show_flags    (buf, bsz, " | ", flags), buf));
		if (show_as & SHOW_AS_APPCTX) printf("appctx->flags = %s\n", (appctx_show_flags(buf, bsz, " | ", flags), buf));
	}
	return 0;
}
