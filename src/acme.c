/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Implements the ACMEv2 RFC 8555 protocol
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <import/ebsttree.h>
#include <import/mjson.h>

#include <haproxy/acme-t.h>

#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/jws.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/tools.h>

static struct acme_cfg *acme_cfgs = NULL;
static struct acme_cfg *cur_acme = NULL;

/* Return an existing acme_cfg section */
struct acme_cfg *get_acme_cfg(const char *name)
{
	struct acme_cfg *tmp_acme = acme_cfgs;

	/* first check if the ID was already used */
	while (tmp_acme) {
		if (strcmp(tmp_acme->name, name) == 0)
			return tmp_acme;

		tmp_acme = tmp_acme->next;
	}
	return NULL;
}

/* Return an existing section section OR create one and return it */
struct acme_cfg *new_acme_cfg(const char *name)
{
	struct acme_cfg *ret = NULL;

	/* first check if the ID was already used. return it if that's the case */
	if ((ret = get_acme_cfg(name)) != NULL)
		goto out;

	/* If there wasn't any section with this name, just create one */
	ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->name = strdup(name);
	/* 0 on the linenum just mean it was not initialized yet */
	ret->linenum = 0;

	ret->challenge = strdup("HTTP-01"); /* default value */

	ret->next = acme_cfgs;
	acme_cfgs = ret;

out:
	return ret;
}

/* acme section parser
 * Fill the acme_cfgs linked list
 */
static int cfg_parse_acme(const char *file, int linenum, char **args, int kwm)
{
	struct cfg_kw_list *kwl;
	const char *best;
	int index;
	int rc = 0;
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "acme") == 0) {
		struct acme_cfg *tmp_acme = acme_cfgs;

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (!*args[1]) {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: section '%s' requires an ID argument.\n", file, linenum, cursection);
			goto out;
		}

		cur_acme = new_acme_cfg(args[1]);
		if (!cur_acme) {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			goto out;
		}


		/* first check if the ID was already used */
		if (cur_acme->linenum > 0) {
			/* an unitialized section is created when parsing the "acme" keyword in a crt-store, with a
			 * linenum <= 0, however, when the linenum > 0, it means we already created a section with this
			 * name */
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: acme section '%s' already exists (%s:%d).\n",
					file, linenum, args[1], tmp_acme->filename, tmp_acme->linenum);
			goto out;
		}

		cur_acme->filename = (char *)file;
		cur_acme->linenum = linenum;

		goto out;
	}

	list_for_each_entry(kwl, &cfg_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].section != CFG_ACME)
				continue;
			if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
				if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
					ha_alert("%s\n", errmsg);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto out;
				}

				/* prepare error message just in case */
				rc = kwl->kw[index].parse(args, CFG_ACME, NULL, NULL, file, linenum, &errmsg);
				if (rc & ERR_ALERT) {
					ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
					err_code |= rc;
					goto out;
				}
				else if (rc & ERR_WARN) {
					ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
					err_code |= rc;
					goto out;
				}
				goto out;
			}
		}
	}

	best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_ACME, NULL);
	if (best)
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n", file, linenum, args[0], cursection, best);
	else
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;

out:
	if (err_code & ERR_FATAL)
		err_code |= ERR_ABORT;
	free(errmsg);
	return err_code;


}

static int cfg_parse_acme_kws(char **args, int section_type, struct proxy *curpx, const struct proxy *defpx,
                              const char *file, int linenum, char **err)
{
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "uri") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires an argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		cur_acme->uri = strdup(args[1]);
		if (!cur_acme->uri) {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			goto out;
		}
	} else if (strcmp(args[0], "contact") == 0) {
		/* save the contact email */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires an argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		cur_acme->account.contact = strdup(args[1]);
		if (!cur_acme->account.contact) {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			goto out;
		}
	} else if (strcmp(args[0], "account") == 0) {
		/* save the filename of the account key */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires a filename argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(2, file, linenum, args, &err_code))
			goto out;

		cur_acme->account.file = strdup(args[1]);
		if (!cur_acme->account.file) {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			goto out;
		}
	} else if (strcmp(args[0], "challenge") == 0) {
		if ((!*args[1]) ||  (strcmp("HTTP-01", args[1]) != 0 && (strcmp("DNS-01", args[1]) != 0))) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires a challenge type: HTTP-01 or DNS-01\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (alertif_too_many_args(2, file, linenum, args, &err_code))
			goto out;

		cur_acme->challenge = strdup(args[1]);
		if (!cur_acme->challenge) {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
			goto out;
		}
	} else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d]: unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
out:
	free(errmsg);
	return err_code;
}

/* Initialize stuff once the section is parsed */
static int cfg_postsection_acme()
{
	struct acme_cfg *cur_acme = acme_cfgs;
	struct ckch_store *store;
	int err_code = 0;
	char *errmsg = NULL;
	char *path;
	struct stat st;

	/* TODO: generate a key at startup and dumps on the filesystem
	 * TODO: use the standard ckch loading for the account key (need a store with only a key)
	 */

	/* if account key filename is unspecified, choose a filename for it */
	if (!cur_acme->account.file) {
		if (!memprintf(&cur_acme->account.file, "%s.account.key", cur_acme->name)) {
			err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
			ha_alert("acme: out of memory.\n");
			goto out;
		}
	}

	path = cur_acme->account.file;

	store = ckch_store_new(path);
	if (!store) {
		ha_alert("acme: out of memory.\n");
		err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
		goto out;
	}
	/* tries to open the account key  */
	if (stat(path, &st) == 0) {
		if (ssl_sock_load_key_into_ckch(path, NULL, store->data, &errmsg)) {
			memprintf(&errmsg, "%s'%s' is present but cannot be read or parsed.\n", errmsg && *errmsg ? errmsg : NULL, path);
			if (errmsg && *errmsg)
				indent_msg(&errmsg, 8);
			err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
			ha_alert("acme: %s\n", errmsg);
			goto out;
		}
		/* ha_notice("acme: reading account key '%s' for id '%s'.\n", path, cur_acme->name); */
	} else {
		ha_alert("%s '%s' is not present and can't be generated, please provide an account file.\n", errmsg, path);
		err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
		goto out;
	}


	if (store->data->key == NULL) {
		ha_alert("acme: No Private Key found in '%s'.\n", path);
		err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
		goto out;
	}

	cur_acme->account.pkey = store->data->key;

	trash.data = jws_thumbprint(cur_acme->account.pkey, trash.area, trash.size);

	cur_acme->account.thumbprint = strndup(trash.area, trash.data);
	if (!cur_acme->account.thumbprint) {
		ha_alert("acme: out of memory.\n");
		err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
		goto out;
	}

	/* insert into the ckchs tree */
	ebst_insert(&ckchs_tree, &store->node);

out:
	ha_free(&errmsg);
	return err_code;
}

void deinit_acme()
{
	struct acme_cfg *next = NULL;

	while (acme_cfgs) {

		next = acme_cfgs->next;
		ha_free(&acme_cfgs->name);
		ha_free(&acme_cfgs->uri);
		ha_free(&acme_cfgs->account.contact);
		ha_free(&acme_cfgs->account.file);
		ha_free(&acme_cfgs->account.thumbprint);

		free(acme_cfgs);
		acme_cfgs = next;
	}
}

static struct cfg_kw_list cfg_kws_acme = {ILH, {
	{ CFG_ACME, "uri",  cfg_parse_acme_kws },
	{ CFG_ACME, "contact",  cfg_parse_acme_kws },
	{ CFG_ACME, "account",  cfg_parse_acme_kws },
	{ CFG_ACME, "challenge",  cfg_parse_acme_kws },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws_acme);

REGISTER_CONFIG_SECTION("acme", cfg_parse_acme, cfg_postsection_acme);


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
