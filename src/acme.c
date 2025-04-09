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

#include <haproxy/cli.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/jws.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_utils.h>
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

	/* The default generated keys are EC-384 */
	ret->key.type = EVP_PKEY_EC;
	ret->key.curves = NID_secp384r1;

	/* default to 4096 bits when using RSA */
	ret->key.bits = 4096;

	ret->next = acme_cfgs;
	acme_cfgs = ret;

out:
	return ret;
}

/*
 * ckch_conf acme parser
 */
int ckch_conf_acme_init(void *value, char *buf, struct ckch_data *d, int cli, const char *filename, int linenum, char **err)
{
	int err_code = 0;
	struct acme_cfg *cfg;

	cfg = new_acme_cfg(value);
	if (!cfg) {
		memprintf(err, "out of memory.\n");
		err_code |= ERR_FATAL| ERR_ALERT;
		goto error;
	}

	if (cfg->linenum == 0) {
		cfg->filename = strdup(filename);
                /* store the linenum as a negative value because is the one of
                 * the crt-store, not the one of the section. It will be replace
                 * by the one of the section once initialized
                 */
                cfg->linenum = -linenum;
	}

error:
	return err_code;
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

	if (!experimental_directives_allowed) {
		ha_alert("parsing [%s:%d]: section '%s' is experimental, must be allowed via a global 'expose-experimental-directives'\n", file, linenum, cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

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

static int cfg_parse_acme_cfg_key(char **args, int section_type, struct proxy *curpx, const struct proxy *defpx,
                              const char *file, int linenum, char **err)
{
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "keytype") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires an argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if (strcmp(args[1], "RSA") == 0) {
			cur_acme->key.type = EVP_PKEY_RSA;
		} else if (strcmp(args[1], "ECDSA") == 0) {
			cur_acme->key.type = EVP_PKEY_EC;
		} else {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires either 'RSA' or 'ECDSA' argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

	} else if (strcmp(args[0], "bits") == 0) {
		char *stop;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires an argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		cur_acme->key.bits = strtol(args[1], &stop, 10);
		if (*stop != '\0') {
			err_code |= ERR_ALERT | ERR_FATAL;
			ha_alert("parsing [%s:%d] : cannot parse '%s' value '%s', an integer is expected.\n", file, linenum, args[0], args[1]);
			goto out;
		}

		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

	} else if (strcmp(args[0], "curves") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d]: keyword '%s' in '%s' section requires an argument\n", file, linenum, args[0], cursection);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;

		if ((cur_acme->key.curves = curves2nid(args[1])) == -1) {
			ha_alert("parsing [%s:%d]: unsupported curves '%s'\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
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

/* postparser function checks if the ACME section was declared */
static int cfg_postparser_acme()
{
	struct acme_cfg *tmp_acme = acme_cfgs;
	int ret = 0;

        /* first check if the ID was already used */
	while (tmp_acme) {
		/* if the linenum is not > 0, it means the acme keyword was used without declaring a section, and the
		 * linenum of the crt-store is stored negatively */
		if (tmp_acme->linenum <= 0) {
			ret++;
			ha_alert("acme '%s' was used on a crt line [%s:%d], but no '%s' section exists!\n",
			         tmp_acme->name, tmp_acme->filename, -tmp_acme->linenum, tmp_acme->name);
		}
		tmp_acme = tmp_acme->next;
	}


	return ret;
}

REGISTER_CONFIG_POSTPARSER("acme", cfg_postparser_acme);

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
	{ CFG_ACME, "keytype",  cfg_parse_acme_cfg_key },
	{ CFG_ACME, "bits",  cfg_parse_acme_cfg_key },
	{ CFG_ACME, "curves",  cfg_parse_acme_cfg_key },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws_acme);

REGISTER_CONFIG_SECTION("acme", cfg_parse_acme, cfg_postsection_acme);

struct task *acme_process(struct task *task, void *context, unsigned int state)
{

	return task;
}


static int cli_acme_renew_parse(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;
	struct acme_cfg *cfg;
	struct task *task;
	struct acme_ctx *ctx = NULL;
	struct ckch_store *store = NULL, *newstore = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (!*args[1]) {
		memprintf(&err, ": not enough parameters\n");
		goto err;
	}

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't update: operations on certificates are currently locked!\n");

	if ((store = ckchs_lookup(args[2])) == NULL) {
		memprintf(&err, "Can't find the certificate '%s'.\n", args[1]);
		goto err;
	}

	if (store->conf.acme.id == NULL) {
		memprintf(&err, "No ACME configuration defined for file '%s'.\n", args[1]);
		goto err;
	}

	cfg = get_acme_cfg(store->conf.acme.id);
	if (!cfg) {
		memprintf(&err, "No ACME configuration found for file '%s'.\n", args[1]);
		goto err;
	}

	newstore = ckch_store_new(store->path);
	if (!newstore) {
		memprintf(&err, "Out of memory.\n");
		goto err;
	}

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	ctx = calloc(1, sizeof *ctx);
	if (!ctx) {
		memprintf(&err, "Out of memory.\n");
		goto err;
	}

	/* set the number of remaining retries when facing an error */
	ctx->retries = ACME_RETRY;

	if ((pkey_ctx = EVP_PKEY_CTX_new_id(cfg->key.type, NULL)) == NULL) {
		memprintf(&err, "%sCan't generate a private key.\n", err ? err : "");
		goto err;
	}

	if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
		memprintf(&err, "%sCan't generate a private key.\n", err ? err : "");
		goto err;
	}

	if (cfg->key.type == EVP_PKEY_EC) {
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, cfg->key.curves) <= 0) {
			memprintf(&err, "%sCan't set the curves on the new private key.\n", err ? err : "");
			goto err;
		}
	} else if (cfg->key.type == EVP_PKEY_RSA) {
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, cfg->key.bits) <= 0) {
			memprintf(&err, "%sCan't set the bits on the new private key.\n", err ? err : "");
			goto err;
		}
	}

	if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
		memprintf(&err, "%sCan't generate a private key.\n", err ? err : "");
		goto err;
	}

	EVP_PKEY_CTX_free(pkey_ctx);

	newstore->data->key = pkey;
	ctx->store = newstore;
	ctx->cfg = cfg;

	task = task_new_anywhere();
	if (!task)
		goto err;
	task->nice = 0;
	task->process = acme_process;
	task->context = ctx;

	task_wakeup(task, TASK_WOKEN_INIT);

	return 0;

err:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	ckch_store_free(newstore);
	EVP_PKEY_CTX_free(pkey_ctx);
	free(ctx);
	memprintf(&err, "%sCan't start the ACME client.\n", err ? err : "");
	return cli_dynerr(appctx, err);
}



static struct cli_kw_list cli_kws = {{ },{
	{ { "acme", "renew", NULL }, NULL, cli_acme_renew_parse, NULL, NULL, NULL, 0 },
	{ { NULL }, NULL, NULL, NULL }
}};


INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
