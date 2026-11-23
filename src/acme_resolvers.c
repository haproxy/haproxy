/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Implements the DNS resolution pre-check for dns-01
 */

#include <haproxy/openssl-compat.h>

#if defined(HAVE_ACME)

#include <stdlib.h>
#include <string.h>


#include <haproxy/acme_resolvers.h>
#include <haproxy/applet.h>
#include <haproxy/obj_type.h>
#include <haproxy/resolvers.h>

static void acme_rslv_clear_txt(struct acme_rslv *rslv)
{
	struct acme_rslv_txt *txt;

	while (rslv->txt) {
		txt = rslv->txt;
		rslv->txt = txt->next;
		istfree(&txt->value);
		free(txt);
	}
}

/* Success callback, copy all TXT records to rslv->txt. */
static int acme_rslv_success_cb(struct resolv_requester *req, struct dns_counters *counters)
{
	struct acme_rslv *rslv = objt_acme_rslv(req->owner);
	struct resolv_resolution *res;
	struct eb32_node *eb32;
	struct resolv_answer_item *item;
	struct acme_rslv_txt *txt;

	if (!rslv)
		return 1;

	rslv->result = RSLV_STATUS_INVALID;
	acme_rslv_clear_txt(rslv);

	res = req->resolution;
	if (!res)
		goto done;

	/* The response tree is shared and its records may be purged after this
	 * callback. Copy each TXT record into an owned list in a single pass.
	 */
	for (eb32 = eb32_first(&res->response.answer_tree); eb32 != NULL; eb32 = eb32_next(eb32)) {
		item = eb32_entry(eb32, typeof(*item), link);
		if (item->type != DNS_RTYPE_TXT)
			continue;
		txt = malloc(sizeof(*txt));
		if (!txt)
			goto error;
		txt->value = istdup(ist2(item->data.target, item->data_len));
		if (!isttest(txt->value)) {
			free(txt);
			goto error;
		}
		txt->next = rslv->txt;
		rslv->txt = txt;
	}
	rslv->result = RSLV_STATUS_VALID;
	goto done;

error:
	acme_rslv_clear_txt(rslv);
done:
	/* if there's no other DNS task for this acme task, wake up acme_task */
	if (HA_ATOMIC_SUB_FETCH(rslv->dnstasks, 1) == 0) {
		if (rslv->acme_task)
			task_wakeup(rslv->acme_task, TASK_WOKEN_MSG);
	}
	return 1;
}

/* error callback, set the error code to rslv->result */
static int acme_rslv_error_cb(struct resolv_requester *req, int error_code)
{
	struct acme_rslv *rslv = objt_acme_rslv(req->owner);

	if (!rslv)
		return 0;

	rslv->result = error_code;
	if (HA_ATOMIC_SUB_FETCH(rslv->dnstasks, 1) == 0) {
		if (rslv->acme_task)
			task_wakeup(rslv->acme_task, TASK_WOKEN_MSG);
	}

	return 0;
}

/* unlink from the resolver and free the acme_rslv */
void acme_rslv_free(struct acme_rslv *rslv)
{
	if (!rslv)
		return;
	if (rslv->requester) {
		HA_SPIN_LOCK(DNS_LOCK, &rslv->resolvers->lock);
		resolv_unlink_resolution(rslv->requester);
		HA_SPIN_UNLOCK(DNS_LOCK, &rslv->resolvers->lock);
	}
	free(rslv->hostname_dn);
	acme_rslv_clear_txt(rslv);
	free(rslv);
}

struct acme_rslv *acme_rslv_start(struct acme_auth *auth, unsigned int *dnstasks, const char *challenge_type, char **errmsg)
{
	struct acme_rslv *rslv = NULL;
	struct resolvers *resolvers;
	char hostname[DNS_MAX_NAME_SIZE + 1];
	char dn[DNS_MAX_NAME_SIZE + 1];
	const char *prefix;
	int hostname_len;
	int dn_len;

	/* XXX: allow to change the resolvers section to use */
	resolvers = find_resolvers_by_id("default");
	if (!resolvers) {
		memprintf(errmsg, "couldn't find the \"default\" resolvers section!\n");
		goto error;
	}

	/* dns-persist-01 TXT record lives at _validation-persist.<domain>,
	 * dns-01 TXT record lives at _acme-challenge.<domain> */
	prefix = (strcasecmp(challenge_type, "dns-persist-01") == 0)
	         ? "_validation-persist"
	         : "_acme-challenge";

	hostname_len = snprintf(hostname, sizeof(hostname), "%s.%.*s",
	                        prefix, (int)auth->dns.len, auth->dns.ptr);
	if (hostname_len < 0 || hostname_len >= (int)sizeof(hostname)) {
		memprintf(errmsg, "hostname \"%s.%.*s\" too long!\n", prefix, (int)auth->dns.len, auth->dns.ptr);
		goto error;
	}

	dn_len = resolv_str_to_dn_label(hostname, hostname_len, dn, sizeof(dn));
	if (dn_len <= 0) {
		memprintf(errmsg, "couldn't convert hostname \"%s.%.*s\" into dn label\n", prefix, (int)auth->dns.len, auth->dns.ptr);
		goto error;
	}

	rslv = calloc(1, sizeof(*rslv));
	if (!rslv) {
		memprintf(errmsg, "Could not allocate memory\n");
		goto error;
	}

	rslv->obj_type      = OBJ_TYPE_ACME_RSLV;
	rslv->resolvers     = resolvers;
	rslv->hostname_dn   = strdup(dn);
	rslv->hostname_dn_len = dn_len;
	rslv->result        = RSLV_STATUS_NONE;
	rslv->success_cb    = acme_rslv_success_cb;
	rslv->error_cb      = acme_rslv_error_cb;
	rslv->dnstasks      = dnstasks;

	if (!rslv->hostname_dn) {
		memprintf(errmsg, "Could not allocate memory\n");
		goto error;
	}

	/* the resolution is processed by the resolvers' thread, which
	 * requires its lock to be held.
	 */
	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);
	if (resolv_link_resolution(rslv, OBJ_TYPE_ACME_RSLV, 0) < 0) {
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
		memprintf(errmsg, "Could not create resolution task for \"%.*s\"\n", hostname_len, hostname);
		goto error;
	}

	resolv_trigger_resolution(rslv->requester);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);

	return rslv;

error:
	if (rslv)
		free(rslv->hostname_dn);
	free(rslv);
	return NULL;
}

#endif /* HAVE_ACME */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
