#include <stdio.h>
#include <stdlib.h>

#include <haproxy/channel-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/stconn-t.h>
#include <haproxy/http_ana-t.h>
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

// command line names, must be in exact same order as the SHOW_AS_* flags above
// so that show_as_words[i] matches flag 1U<<i.
const char *show_as_words[] = { "ana", "chn", "conn", "sc", "stet", "strm", "task", "txn", "sd", };

#define SHOW_FLAG(f,n)					\
	do {				 		\
		if (!((f) & (n))) break; 		\
		(f) &= ~(n);				\
		printf(#n"%s", (f) ? " | " : "");	\
	} while (0)

/* will be sufficient for even largest flag names */
static char tmpbuf[4096];

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

void show_chn_ana(unsigned int f)
{
	chn_show_analysers(tmpbuf, sizeof(tmpbuf), " | ", f);
	printf("chn->ana    = %s\n", tmpbuf);
}

void show_chn_flags(unsigned int f)
{
	chn_show_flags(tmpbuf, sizeof(tmpbuf), " | ", f);
	printf("chn->flags  = %s\n", tmpbuf);
}

void show_conn_flags(unsigned int f)
{
	conn_show_flags(tmpbuf, sizeof(tmpbuf), " | ", f);
	printf("conn->flags = %s\n", tmpbuf);
}

void show_sd_flags(unsigned int f)
{
	se_show_flags(tmpbuf, sizeof(tmpbuf), " | ", f);
	printf("sd->flags = %s\n", tmpbuf);
}

void show_sc_flags(unsigned int f)
{
	sc_show_flags(tmpbuf, sizeof(tmpbuf), " | ", f);
	printf("sc->flags = %s\n", tmpbuf);
}

void show_strm_et(unsigned int f)
{
	strm_et_show_flags(tmpbuf, sizeof(tmpbuf), " | ", f);
	printf("strm->et = %s\n", tmpbuf);
}

void show_task_state(unsigned int f)
{
	printf("task->state = ");

	if (!f) {
		printf("TASK_SLEEPING\n");
		return;
	}

	SHOW_FLAG(f, TASK_F_USR1);
	SHOW_FLAG(f, TASK_F_TASKLET);
	SHOW_FLAG(f, TASK_WOKEN_OTHER);
	SHOW_FLAG(f, TASK_WOKEN_RES);
	SHOW_FLAG(f, TASK_WOKEN_MSG);
	SHOW_FLAG(f, TASK_WOKEN_SIGNAL);
	SHOW_FLAG(f, TASK_WOKEN_IO);
	SHOW_FLAG(f, TASK_WOKEN_TIMER);
	SHOW_FLAG(f, TASK_WOKEN_INIT);
	SHOW_FLAG(f, TASK_HEAVY);
	SHOW_FLAG(f, TASK_IN_LIST);
	SHOW_FLAG(f, TASK_KILLED);
	SHOW_FLAG(f, TASK_SELF_WAKING);
	SHOW_FLAG(f, TASK_QUEUED);
	SHOW_FLAG(f, TASK_RUNNING);

	if (f) {
		printf("EXTRA(0x%08x)", f);
	}
	putchar('\n');
}

void show_txn_flags(unsigned int f)
{
	printf("txn->flags  = ");

	if (!f) {
		printf("0\n");
		return;
	}

	SHOW_FLAG(f, TX_L7_RETRY);
	SHOW_FLAG(f, TX_D_L7_RETRY);
	SHOW_FLAG(f, TX_NOT_FIRST);
	SHOW_FLAG(f, TX_USE_PX_CONN);
	SHOW_FLAG(f, TX_CACHE_HAS_SEC_KEY);
	SHOW_FLAG(f, TX_CON_WANT_TUN);

	SHOW_FLAG(f, TX_CACHE_IGNORE);
	SHOW_FLAG(f, TX_CACHE_COOK);
	SHOW_FLAG(f, TX_CACHEABLE);
	SHOW_FLAG(f, TX_SCK_PRESENT);

	//printf("%s", f ? "" : " | ");
	switch (f & TX_SCK_MASK) {
	case TX_SCK_NONE:                        f &= ~TX_SCK_MASK ; /*printf("TX_SCK_NONE%s",     f ? " | " : "");*/ break;
	case TX_SCK_FOUND:                       f &= ~TX_SCK_MASK ; printf("TX_SCK_FOUND%s",    f ? " | " : ""); break;
	case TX_SCK_DELETED:                     f &= ~TX_SCK_MASK ; printf("TX_SCK_DELETED%s",  f ? " | " : ""); break;
	case TX_SCK_INSERTED:                    f &= ~TX_SCK_MASK ; printf("TX_SCK_INSERTED%s", f ? " | " : ""); break;
	case TX_SCK_REPLACED:                    f &= ~TX_SCK_MASK ; printf("TX_SCK_REPLACED%s", f ? " | " : ""); break;
	case TX_SCK_UPDATED:                     f &= ~TX_SCK_MASK ; printf("TX_SCK_UPDATED%s",  f ? " | " : ""); break;
	default: printf("TX_SCK_MASK(%02x)", f); f &= ~TX_SCK_MASK ; printf("%s",                f ? " | " : ""); break;
	}

	//printf("%s", f ? "" : " | ");
	switch (f & TX_CK_MASK) {
	case TX_CK_NONE:                        f &= ~TX_CK_MASK ; /*printf("TX_CK_NONE%s",    f ? " | " : "");*/ break;
	case TX_CK_INVALID:                     f &= ~TX_CK_MASK ; printf("TX_CK_INVALID%s", f ? " | " : ""); break;
	case TX_CK_DOWN:                        f &= ~TX_CK_MASK ; printf("TX_CK_DOWN%s",    f ? " | " : ""); break;
	case TX_CK_VALID:                       f &= ~TX_CK_MASK ; printf("TX_CK_VALID%s",   f ? " | " : ""); break;
	case TX_CK_EXPIRED:                     f &= ~TX_CK_MASK ; printf("TX_CK_EXPIRED%s", f ? " | " : ""); break;
	case TX_CK_OLD:                         f &= ~TX_CK_MASK ; printf("TX_CK_OLD%s",     f ? " | " : ""); break;
	case TX_CK_UNUSED:                      f &= ~TX_CK_MASK ; printf("TX_CK_UNUSED%s",  f ? " | " : ""); break;
	default: printf("TX_CK_MASK(%02x)", f); f &= ~TX_CK_MASK ; printf("%s",              f ? " | " : ""); break;
	}

	SHOW_FLAG(f, TX_CLTARPIT);
	SHOW_FLAG(f, TX_CONST_REPLY);

	if (f) {
		printf("EXTRA(0x%08x)", f);
	}
	putchar('\n');
}

void show_strm_flags(unsigned int f)
{
	printf("strm->flags = ");

	if (!f) {
		printf("0\n");
		return;
	}

	SHOW_FLAG(f, SF_SRC_ADDR);
	SHOW_FLAG(f, SF_WEBSOCKET);
	SHOW_FLAG(f, SF_SRV_REUSED_ANTICIPATED);
	SHOW_FLAG(f, SF_SRV_REUSED);
	SHOW_FLAG(f, SF_IGNORE_PRST);

	//printf("%s", f ? "" : " | ");
	switch (f & SF_FINST_MASK) {
	case SF_FINST_R: f &= ~SF_FINST_MASK ; printf("SF_FINST_R%s", f ? " | " : ""); break;
	case SF_FINST_C: f &= ~SF_FINST_MASK ; printf("SF_FINST_C%s", f ? " | " : ""); break;
	case SF_FINST_H: f &= ~SF_FINST_MASK ; printf("SF_FINST_H%s", f ? " | " : ""); break;
	case SF_FINST_D: f &= ~SF_FINST_MASK ; printf("SF_FINST_D%s", f ? " | " : ""); break;
	case SF_FINST_L: f &= ~SF_FINST_MASK ; printf("SF_FINST_L%s", f ? " | " : ""); break;
	case SF_FINST_Q: f &= ~SF_FINST_MASK ; printf("SF_FINST_Q%s", f ? " | " : ""); break;
	case SF_FINST_T: f &= ~SF_FINST_MASK ; printf("SF_FINST_T%s", f ? " | " : ""); break;
	}

	switch (f & SF_ERR_MASK) {
	case SF_ERR_LOCAL:    f &= ~SF_ERR_MASK ; printf("SF_ERR_LOCAL%s",    f ? " | " : ""); break;
	case SF_ERR_CLITO:    f &= ~SF_ERR_MASK ; printf("SF_ERR_CLITO%s",    f ? " | " : ""); break;
	case SF_ERR_CLICL:    f &= ~SF_ERR_MASK ; printf("SF_ERR_CLICL%s",    f ? " | " : ""); break;
	case SF_ERR_SRVTO:    f &= ~SF_ERR_MASK ; printf("SF_ERR_SRVTO%s",    f ? " | " : ""); break;
	case SF_ERR_SRVCL:    f &= ~SF_ERR_MASK ; printf("SF_ERR_SRVCL%s",    f ? " | " : ""); break;
	case SF_ERR_PRXCOND:  f &= ~SF_ERR_MASK ; printf("SF_ERR_PRXCOND%s",  f ? " | " : ""); break;
	case SF_ERR_RESOURCE: f &= ~SF_ERR_MASK ; printf("SF_ERR_RESOURCE%s", f ? " | " : ""); break;
	case SF_ERR_INTERNAL: f &= ~SF_ERR_MASK ; printf("SF_ERR_INTERNAL%s", f ? " | " : ""); break;
	case SF_ERR_DOWN:     f &= ~SF_ERR_MASK ; printf("SF_ERR_DOWN%s",     f ? " | " : ""); break;
	case SF_ERR_KILLED:   f &= ~SF_ERR_MASK ; printf("SF_ERR_KILLED%s",   f ? " | " : ""); break;
	case SF_ERR_UP:       f &= ~SF_ERR_MASK ; printf("SF_ERR_UP%s",       f ? " | " : ""); break;
	case SF_ERR_CHK_PORT: f &= ~SF_ERR_MASK ; printf("SF_ERR_CHK_PORT%s",       f ? " | " : ""); break;
	}

	SHOW_FLAG(f, SF_HTX);
	SHOW_FLAG(f, SF_REDIRECTABLE);
	SHOW_FLAG(f, SF_IGNORE);
	SHOW_FLAG(f, SF_REDISP);
	SHOW_FLAG(f, SF_CONN_EXP);
	SHOW_FLAG(f, SF_CURR_SESS);
	SHOW_FLAG(f, SF_MONITOR);
	SHOW_FLAG(f, SF_FORCE_PRST);
	SHOW_FLAG(f, SF_BE_ASSIGNED);
	SHOW_FLAG(f, SF_ASSIGNED);
	SHOW_FLAG(f, SF_DIRECT);

	if (f) {
		printf("EXTRA(0x%08x)", f);
	}
	putchar('\n');
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

		if (show_as & SHOW_AS_ANA)   show_chn_ana(flags);
		if (show_as & SHOW_AS_CHN)   show_chn_flags(flags);
		if (show_as & SHOW_AS_CONN)  show_conn_flags(flags);
		if (show_as & SHOW_AS_SC)    show_sc_flags(flags);
		if (show_as & SHOW_AS_SD)    show_sd_flags(flags);
		if (show_as & SHOW_AS_SET)   show_strm_et(flags);
		if (show_as & SHOW_AS_STRM)  show_strm_flags(flags);
		if (show_as & SHOW_AS_TASK)  show_task_state(flags);
		if (show_as & SHOW_AS_TXN)   show_txn_flags(flags);
	}
	return 0;
}
