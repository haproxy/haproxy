/*
 * Mailer management.
 *
 * Copyright 2015 Horms Solutions Ltd, Simon Horman <horms@verge.net.au>
 * Copyright 2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/check.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/mailers.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/task.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>


struct mailers *mailers = NULL;

/* Set to 1 to disable email sending through checks even if the
 * mailers are configured to do so. (e.g.: disable from lua)
 */
int send_email_disabled = 0;

DECLARE_STATIC_POOL(pool_head_email_alert,   "email_alert",   sizeof(struct email_alert));

/****************************** Email alerts ******************************/
/* NOTE: It may be pertinent to use an applet to handle email alerts      */
/*        instead of a tcp-check ruleset                                  */
/**************************************************************************/
void email_alert_free(struct email_alert *alert)
{
	struct tcpcheck_rule *rule, *back;

	if (!alert)
		return;

	if (alert->rules.list) {
		list_for_each_entry_safe(rule, back, alert->rules.list, list) {
			LIST_DELETE(&rule->list);
			free_tcpcheck(rule, 1);
		}
		free_tcpcheck_vars(&alert->rules.preset_vars);
		ha_free(&alert->rules.list);
	}
	pool_free(pool_head_email_alert, alert);
}

static struct task *process_email_alert(struct task *t, void *context, unsigned int state)
{
	struct check        *check = context;
	struct email_alertq *q;
	struct email_alert  *alert;

	q = container_of(check, typeof(*q), check);

	HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);
	while (1) {
		if (!(check->state & CHK_ST_ENABLED)) {
			if (LIST_ISEMPTY(&q->email_alerts)) {
				/* All alerts processed, queue the task */
				t->expire = TICK_ETERNITY;
				task_queue(t);
				goto end;
			}

			alert = LIST_NEXT(&q->email_alerts, typeof(alert), list);
			LIST_DELETE(&alert->list);
			t->expire             = tick_add(now_ms, 0);
			check->tcpcheck_rules = &alert->rules;
			check->status         = HCHK_STATUS_INI;
			check->state         |= CHK_ST_ENABLED;
		}

		process_chk(t, context, state);
		if (check->state & CHK_ST_INPROGRESS)
			break;

		alert = container_of(check->tcpcheck_rules, typeof(*alert), rules);
		email_alert_free(alert);
		check->tcpcheck_rules = NULL;
		check->server         = NULL;
		check->state         &= ~CHK_ST_ENABLED;
	}
  end:
	HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);
	return t;
}

/* Initializes mailer alerts for the proxy <p> using <mls> parameters.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int init_email_alert(struct mailers *mls, struct proxy *p, char **err)
{
	struct mailer       *mailer;
	struct email_alertq *queues;
	const char          *err_str;
	int                  i = 0;

	if (!send_email_disabled)
		ha_warning("Legacy mailers used by %s '%s' will not be supported anymore in version 3.3. You should use Lua to send email-alerts, see 'examples/lua/mailers.lua' file.\n",
			   proxy_type_str(p), p->id);

	if ((queues = calloc(mls->count, sizeof(*queues))) == NULL) {
		memprintf(err, "out of memory while allocating mailer alerts queues");
		goto fail_no_queue;
	}

	for (mailer = mls->mailer_list; mailer; i++, mailer = mailer->next) {
		struct email_alertq *q     = &queues[i];
		struct check        *check = &q->check;
		struct task         *t;

		LIST_INIT(&q->email_alerts);
		HA_SPIN_INIT(&q->lock);
		check->obj_type = OBJ_TYPE_CHECK;
		check->inter = mls->timeout.mail;
		check->rise = DEF_AGENT_RISETIME;
		check->proxy = p;
		check->fall = DEF_AGENT_FALLTIME;
		if ((err_str = init_check(check, PR_O2_TCPCHK_CHK))) {
			memprintf(err, "%s", err_str);
			goto error;
		}

		check->xprt = mailer->xprt;
		check->addr = mailer->addr;
		check->port = get_host_port(&mailer->addr);

		if ((t = task_new_anywhere()) == NULL) {
			memprintf(err, "out of memory while allocating mailer alerts task");
			goto error;
		}

		check->task = t;
		t->process = process_email_alert;
		t->context = check;

		/* check this in one ms */
		t->expire    = TICK_ETERNITY;
		check->start = now_ns;
		task_queue(t);
	}

	mls->users++;
	free(p->email_alert.mailers.name);
	p->email_alert.mailers.m = mls;
	p->email_alert.flags |= PR_EMAIL_ALERT_RESOLVED;
	p->email_alert.queues    = queues;
	return 0;

  error:
	for (i = 0; i < mls->count; i++) {
		struct email_alertq *q     = &queues[i];
		struct check        *check = &q->check;

		free_check(check);
	}
	free(queues);
  fail_no_queue:
	return 1;
}

void free_email_alert(struct proxy *p)
{
	if (!(p->email_alert.flags & PR_EMAIL_ALERT_RESOLVED))
		ha_free(&p->email_alert.mailers.name);
	ha_free(&p->email_alert.from);
	ha_free(&p->email_alert.to);
	ha_free(&p->email_alert.myhostname);
}

static int enqueue_one_email_alert(struct proxy *p, struct server *s,
				   struct email_alertq *q, const char *msg)
{
	struct email_alert   *alert;
	struct tcpcheck_rule *tcpcheck;
	struct check *check = &q->check;

	if ((alert = pool_alloc(pool_head_email_alert)) == NULL)
		goto error;
	LIST_INIT(&alert->list);
	alert->rules.flags = TCPCHK_RULES_TCP_CHK;
	alert->rules.list = calloc(1, sizeof(*alert->rules.list));
	if (!alert->rules.list)
		goto error;
	LIST_INIT(alert->rules.list);
	LIST_INIT(&alert->rules.preset_vars); /* unused for email alerts */
	alert->srv = s;

	if ((tcpcheck = pool_zalloc(pool_head_tcpcheck_rule)) == NULL)
		goto error;
	tcpcheck->action       = TCPCHK_ACT_CONNECT;
	tcpcheck->comment      = NULL;

	LIST_APPEND(alert->rules.list, &tcpcheck->list);

	if (!add_tcpcheck_expect_str(&alert->rules, "220 "))
		goto error;

	{
		const char * const strs[4] = { "HELO ", p->email_alert.myhostname, "\r\n" };
		if (!add_tcpcheck_send_strs(&alert->rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->rules, "250 "))
		goto error;

	{
		const char * const strs[4] = { "MAIL FROM:<", p->email_alert.from, ">\r\n" };
		if (!add_tcpcheck_send_strs(&alert->rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->rules, "250 "))
		goto error;

	{
		const char * const strs[4] = { "RCPT TO:<", p->email_alert.to, ">\r\n" };
		if (!add_tcpcheck_send_strs(&alert->rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->rules, "250 "))
		goto error;

	{
		const char * const strs[2] = { "DATA\r\n" };
		if (!add_tcpcheck_send_strs(&alert->rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->rules, "354 "))
		goto error;

	{
		struct tm tm;
		char datestr[48];
		const char * const strs[18] = {
			"From: ", p->email_alert.from, "\r\n",
			"To: ", p->email_alert.to, "\r\n",
			"Date: ", datestr, "\r\n",
			"Subject: [HAProxy Alert] ", msg, "\r\n",
			"\r\n",
			msg, "\r\n",
			"\r\n",
			".\r\n",
			NULL
		};

		get_localtime(date.tv_sec, &tm);

		if (strftime(datestr, sizeof(datestr), "%a, %d %b %Y %T %z (%Z)", &tm) == 0) {
			goto error;
		}

		if (!add_tcpcheck_send_strs(&alert->rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->rules, "250 "))
		goto error;

	{
		const char * const strs[2] = { "QUIT\r\n" };
		if (!add_tcpcheck_send_strs(&alert->rules, strs))
			goto error;
	}

	if (!add_tcpcheck_expect_str(&alert->rules, "221 "))
		goto error;

	HA_SPIN_LOCK(EMAIL_ALERTS_LOCK, &q->lock);
	task_wakeup(check->task, TASK_WOKEN_MSG);
	LIST_APPEND(&q->email_alerts, &alert->list);
	HA_SPIN_UNLOCK(EMAIL_ALERTS_LOCK, &q->lock);
	return 1;

error:
	email_alert_free(alert);
	return 0;
}

static void enqueue_email_alert(struct proxy *p, struct server *s, const char *msg)
{
	int i;
	struct mailer *mailer;

	for (i = 0, mailer = p->email_alert.mailers.m->mailer_list;
	     i < p->email_alert.mailers.m->count; i++, mailer = mailer->next) {
		if (!enqueue_one_email_alert(p, s, &p->email_alert.queues[i], msg)) {
			ha_alert("Email alert [%s] could not be enqueued: out of memory\n", p->id);
			return;
		}
	}

	return;
}

/*
 * Send email alert if configured.
 */
void send_email_alert(struct server *s, int level, const char *format, ...)
{
	va_list argp;
	char buf[1024];
	int len;
	struct proxy *p = s->proxy;

	if (send_email_disabled)
		return;

	if (!p->email_alert.mailers.m || level > p->email_alert.level || format == NULL)
		return;

	va_start(argp, format);
	len = vsnprintf(buf, sizeof(buf), format, argp);
	va_end(argp);

	if (len < 0 || len >= sizeof(buf)) {
		ha_alert("Email alert [%s] could not format message\n", p->id);
		return;
	}

	enqueue_email_alert(p, s, buf);
}
