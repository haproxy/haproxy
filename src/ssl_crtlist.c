/*
 *
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <import/ebpttree.h>
#include <import/ebsttree.h>

#include <haproxy/applet.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/sc_strm.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_crtlist.h>
#include <haproxy/ssl_ocsp.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stconn.h>
#include <haproxy/tools.h>

/* CLI context for "show ssl crt-list" or "dump ssl crt-list" */
struct show_crtlist_ctx {
	struct ebmb_node *crtlist_node;  /* ebmb_node for the current crtlist */
	struct crtlist_entry *entry;     /* current entry */
	int mode;                        /* 'd' for dump, 's' for show */
};

/* CLI context for "add ssl crt-list" */
struct add_crtlist_ctx {
	struct crtlist *crtlist;
	struct crtlist_entry *entry;
	struct bind_conf_list *bind_conf_node;
	char *err;
	enum {
		ADDCRT_ST_INIT = 0,
		ADDCRT_ST_GEN,
		ADDCRT_ST_INSERT,
		ADDCRT_ST_SUCCESS,
		ADDCRT_ST_ERROR,
		ADDCRT_ST_FIN,
	} state;
};

/* release ssl bind conf */
void ssl_sock_free_ssl_conf(struct ssl_bind_conf *conf)
{
	if (conf) {
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
		ha_free(&conf->npn_str);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		ha_free(&conf->alpn_str);
#endif
		ha_free(&conf->ca_file);
		ha_free(&conf->ca_verify_file);
		ha_free(&conf->crl_file);
		ha_free(&conf->ciphers);
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
		ha_free(&conf->ciphersuites);
#endif
		ha_free(&conf->curves);
		ha_free(&conf->ecdhe);
#if defined(SSL_CTX_set1_sigalgs_list)
		ha_free(&conf->sigalgs);
#endif
#if defined(SSL_CTX_set1_client_sigalgs_list)
		ha_free(&conf->client_sigalgs);
#endif
	}
}

/*
 * Allocate and copy a ssl_bind_conf structure
 */
struct ssl_bind_conf *crtlist_dup_ssl_conf(struct ssl_bind_conf *src)
{
	struct ssl_bind_conf *dst;

	if (!src)
		return NULL;

	dst = calloc(1, sizeof(*dst));
	if (!dst)
		return NULL;

#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	if (src->npn_str) {
		dst->npn_str = strdup(src->npn_str);
		if (!dst->npn_str)
			goto error;
	}
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (src->alpn_str) {
		dst->alpn_str = strdup(src->alpn_str);
		if (!dst->alpn_str)
			goto error;
	}
#endif
	if (src->ca_file) {
		dst->ca_file = strdup(src->ca_file);
		if (!dst->ca_file)
			goto error;
	}
	if (src->ca_verify_file) {
		dst->ca_verify_file = strdup(src->ca_verify_file);
		if (!dst->ca_verify_file)
			goto error;
	}
	if (src->crl_file) {
		dst->crl_file = strdup(src->crl_file);
		if (!dst->crl_file)
			goto error;
	}
	if (src->ciphers) {
		dst->ciphers = strdup(src->ciphers);
		if (!dst->ciphers)
			goto error;
	}
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (src->ciphersuites) {
		dst->ciphersuites = strdup(src->ciphersuites);
		if (!dst->ciphersuites)
			goto error;
	}
#endif
	if (src->curves) {
		dst->curves = strdup(src->curves);
		if (!dst->curves)
			goto error;
	}
	if (src->ecdhe) {
		dst->ecdhe = strdup(src->ecdhe);
		if (!dst->ecdhe)
			goto error;
	}

	dst->ssl_methods_cfg.flags = src->ssl_methods_cfg.flags;
	dst->ssl_methods_cfg.min = src->ssl_methods_cfg.min;
	dst->ssl_methods_cfg.max = src->ssl_methods_cfg.max;

	dst->ssl_methods.flags = src->ssl_methods.flags;
	dst->ssl_methods.min = src->ssl_methods.min;
	dst->ssl_methods.max = src->ssl_methods.max;

#if defined(SSL_CTX_set1_sigalgs_list)
	if (src->sigalgs) {
		dst->sigalgs = strdup(src->sigalgs);
		if (!dst->sigalgs)
			goto error;
	}
#endif
#if defined(SSL_CTX_set1_client_sigalgs_list)
	if (src->client_sigalgs) {
		dst->client_sigalgs = strdup(src->client_sigalgs);
		if (!dst->client_sigalgs)
			goto error;
	}
#endif
	return dst;

error:
	ssl_sock_free_ssl_conf(dst);
	free(dst);

	return NULL;
}

/* free sni filters */
void crtlist_free_filters(char **args)
{
	int i;

	if (!args)
		return;

	for (i = 0; args[i]; i++)
		free(args[i]);

	free(args);
}

/* Alloc and duplicate a char ** array */
char **crtlist_dup_filters(char **args, int fcount)
{
	char **dst;
	int i;

	if (fcount == 0)
		return NULL;

	dst = calloc(fcount + 1, sizeof(*dst));
	if (!dst)
		return NULL;

	for (i = 0; i < fcount; i++) {
		dst[i] = strdup(args[i]);
		if (!dst[i])
			goto error;
	}
	return dst;

error:
	crtlist_free_filters(dst);
	return NULL;
}

/*
 * Detach and free a crtlist_entry.
 * Free the filters, the ssl_conf and call ckch_inst_free() for each ckch_inst
 */
void crtlist_entry_free(struct crtlist_entry *entry)
{
	struct ckch_inst *inst, *inst_s;

	if (entry == NULL)
		return;

	ebpt_delete(&entry->node);
	LIST_DELETE(&entry->by_crtlist);
	LIST_DELETE(&entry->by_ckch_store);
	crtlist_free_filters(entry->filters);
	ssl_sock_free_ssl_conf(entry->ssl_conf);
	free(entry->ssl_conf);
	list_for_each_entry_safe(inst, inst_s, &entry->ckch_inst, by_crtlist_entry) {
		ckch_inst_free(inst);
	}
	free(entry);
}
/*
 * Duplicate a crt_list entry and its content (ssl_conf, filters/fcount)
 * Return a pointer to the new entry
 */
struct crtlist_entry *crtlist_entry_dup(struct crtlist_entry *src)
{
	struct crtlist_entry *entry;

	if (src == NULL)
		return NULL;

	entry = crtlist_entry_new();
	if (entry == NULL)
		return NULL;

	if (src->filters) {
		entry->filters = crtlist_dup_filters(src->filters, src->fcount);
		if (!entry->filters)
			goto error;
	}
	entry->fcount = src->fcount;
	if (src->ssl_conf) {
		entry->ssl_conf = crtlist_dup_ssl_conf(src->ssl_conf);
		if (!entry->ssl_conf)
			goto error;
	}
	entry->crtlist = src->crtlist;

	return entry;

error:

	crtlist_free_filters(entry->filters);
	ssl_sock_free_ssl_conf(entry->ssl_conf);
	free(entry->ssl_conf);
	free(entry);

	return NULL;
}

/*
 * Allocate and initialize a crtlist_entry
 */
struct crtlist_entry *crtlist_entry_new()
{
	struct crtlist_entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	LIST_INIT(&entry->ckch_inst);

	/* initialize the nodes so we can LIST_DELETE in any cases */
	LIST_INIT(&entry->by_crtlist);
	LIST_INIT(&entry->by_ckch_store);

	return entry;
}

/* Free a crtlist, from the crt_entry to the content of the ssl_conf */
void crtlist_free(struct crtlist *crtlist)
{
	struct crtlist_entry *entry, *s_entry;
	struct bind_conf_list *bind_conf_node;

	if (crtlist == NULL)
		return;

	bind_conf_node = crtlist->bind_conf;
	while (bind_conf_node) {
		struct bind_conf_list *next = bind_conf_node->next;
		free(bind_conf_node);
		bind_conf_node = next;
	}

	list_for_each_entry_safe(entry, s_entry, &crtlist->ord_entries, by_crtlist) {
		crtlist_entry_free(entry);
	}
	ebmb_delete(&crtlist->node);
	free(crtlist);
}

/* Alloc and initialize a struct crtlist
 * <filename> is the key of the ebmb_node
 * <unique> initialize the list of entries to be unique (1) or not (0)
 */
struct crtlist *crtlist_new(const char *filename, int unique)
{
	struct crtlist *newlist;

	newlist = calloc(1, sizeof(*newlist) + strlen(filename) + 1);
	if (newlist == NULL)
		return NULL;

	memcpy(newlist->node.key, filename, strlen(filename) + 1);
	if (unique)
		newlist->entries = EB_ROOT_UNIQUE;
	else
		newlist->entries = EB_ROOT;

	LIST_INIT(&newlist->ord_entries);

	return newlist;
}

/*
 *  Read a single crt-list line. /!\ alter the <line> string.
 *  Fill <crt_path> and <crtlist_entry>
 *  <crtlist_entry> must be alloc and free by the caller
 *  <crtlist_entry->ssl_conf> is alloc by the function
 *  <crtlist_entry->filters> is alloc by the function
 *  <crt_path> is a ptr in <line>
 *  Return an error code
 */
int crtlist_parse_line(char *line, char **crt_path, struct crtlist_entry *entry, struct ckch_conf *cc, const char *file, int linenum, int from_cli, char **err)
{
	int cfgerr = 0;
	int arg, newarg, cur_arg, i, ssl_b = 0, ssl_e = 0;
	char *end;
	char *args[MAX_CRT_ARGS + 1];
	struct ssl_bind_conf *ssl_conf = NULL;

	if (!line || !crt_path || !entry)
		return ERR_ALERT | ERR_FATAL;

	end = line + strlen(line);
	if (end-line >= CRT_LINESIZE-1 && *(end-1) != '\n') {
		/* Check if we reached the limit and the last char is not \n.
		 * Watch out for the last line without the terminating '\n'!
		 */
		memprintf(err, "parsing [%s:%d]: line too long, limit is %d characters",
		          file, linenum, CRT_LINESIZE-1);
		cfgerr |= ERR_ALERT | ERR_FATAL;
		goto error;
	}
	arg = 0;
	newarg = 1;
	while (*line) {
		if (isspace((unsigned char)*line)) {
			newarg = 1;
			*line = 0;
		} else if (*line == '[') {
			if (ssl_b) {
				memprintf(err, "parsing [%s:%d]: too many '['", file, linenum);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			if (!arg) {
				memprintf(err, "parsing [%s:%d]: file must start with a cert", file, linenum);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			ssl_b = arg;
			newarg = 1;
			*line = 0;
		} else if (*line == ']') {
			if (ssl_e) {
				memprintf(err, "parsing [%s:%d]: too many ']'", file, linenum);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			if (!ssl_b) {
				memprintf(err, "parsing [%s:%d]: missing '['", file, linenum);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			ssl_e = arg;
			newarg = 1;
			*line = 0;
		} else if (newarg) {
			if (arg == MAX_CRT_ARGS) {
				memprintf(err, "parsing [%s:%d]: too many args ", file, linenum);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			newarg = 0;
			args[arg++] = line;
		}
		line++;
	}
	args[arg++] = line;

	/* empty line */
	if (!*args[0]) {
		cfgerr |= ERR_NONE;
		goto error;
	}

	*crt_path = args[0];

	if (ssl_b) {
		if (ssl_b > 1) {
			memprintf(err, "parsing [%s:%d]: malformated line, filters can't be between filename and options!", file, linenum);
			cfgerr |= ERR_WARN;
		}

	}

	cur_arg = ssl_b ? ssl_b : 1;
	while (cur_arg < ssl_e) {
		newarg = 0;
		/* look for ssl_conf keywords */
		for (i = 0; ssl_crtlist_kws[i].kw != NULL; i++) {
			if (strcmp(ssl_crtlist_kws[i].kw, args[cur_arg]) == 0) {
				if (!ssl_conf)
					ssl_conf = calloc(1, sizeof *ssl_conf);
				if (!ssl_conf) {
					memprintf(err, "not enough memory!");
					cfgerr |= ERR_ALERT | ERR_FATAL;
					goto error;
				}

				newarg = 1;
				cfgerr |= ssl_crtlist_kws[i].parse(args, cur_arg, NULL, ssl_conf, from_cli, err);
				if (cur_arg + 1 + ssl_crtlist_kws[i].skip > ssl_e) {
					memprintf(err, "parsing [%s:%d]: ssl args out of '[]' for %s",
					          file, linenum, args[cur_arg]);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					goto error;
				}
				cur_arg += 1 + ssl_crtlist_kws[i].skip;
				goto out;
			}
		}
		if (cc) {
			/* look for ckch_conf keywords */
			cfgerr |= ckch_conf_parse(args, cur_arg, cc, &newarg, file, linenum, err);
			if (cfgerr & ERR_FATAL)
				goto error;

			if (newarg) {
				cur_arg += 2;  /* skip 2 words if the keyword was found */
				cc->used = CKCH_CONF_SET_CRTLIST; /* if they are options they must be used everywhere */
			}

		}
out:
		if (!cfgerr && !newarg) {
			memprintf(err, "parsing [%s:%d]: unknown ssl keyword %s",
				  file, linenum, args[cur_arg]);
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto error;
		}
	}
	entry->linenum = linenum;
	entry->ssl_conf = ssl_conf;
	entry->filters = crtlist_dup_filters(&args[cur_arg], arg - cur_arg - 1);
	entry->fcount = arg - cur_arg - 1;

	return cfgerr;

error:
	crtlist_free_filters(entry->filters);
	entry->filters = NULL;
	ssl_sock_free_ssl_conf(entry->ssl_conf);
	ha_free(&entry->ssl_conf);
	return cfgerr;
}

/*
 * Look for a ckch_store <crt_path> which is a compatible with <cc>
 * Or create a new ckch_store if none exists with this name.
 *
 * If the file is a bundle, then duplicate the entries
 * Then insert the entries in the list
 */
int crtlist_load_crt(char *crt_path, struct ckch_conf *cc, struct crtlist *newlist, struct crtlist_entry *entry, char *file, int linenum, char **err)
{
	struct ckch_store *ckchs;
	int found = 0;
	struct stat st;
	int cfgerr = 0;

	/* Look for a ckch_store or create one */
	ckchs = ckchs_lookup(crt_path);
	if (ckchs == NULL) {
		if (stat(crt_path, &st) == 0) {
			found++;

			if (crt_path != cc->crt) {
				free(cc->crt);
				cc->crt = strdup(crt_path);
				if (cc->crt == NULL) {
					cfgerr |= ERR_ALERT | ERR_FATAL;
					goto error;
				}
			}

			ckchs = ckch_store_new_load_files_conf(crt_path, cc, file, linenum, err);
			if (ckchs == NULL) {
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}

			ckchs->conf = *cc;

			entry->node.key = ckchs;
			entry->crtlist = newlist;
			ebpt_insert(&newlist->entries, &entry->node);
			LIST_APPEND(&newlist->ord_entries, &entry->by_crtlist);
			LIST_APPEND(&ckchs->crtlist_entry, &entry->by_ckch_store);

		} else if (global_ssl.extra_files & SSL_GF_BUNDLE) {
			/* If we didn't find the file, this could be a
			   bundle, since 2.3 we don't support multiple
			   certificate in the same OpenSSL store, so we
			   emulate it by loading each file separately. To
			   do so we need to duplicate the entry in the
			   crt-list because it becomes independent */
			char fp[MAXPATHLEN+1] = {0};
			int n = 0;
			struct crtlist_entry *entry_dup = entry; /* use the previous created entry */

			for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
				int ret;

				ret = snprintf(fp, sizeof(fp), "%s.%s", crt_path, SSL_SOCK_KEYTYPE_NAMES[n]);
				if (ret > sizeof(fp))
					continue;

				ckchs = ckchs_lookup(fp);
				if (!ckchs) {
					if (stat(fp, &st) == 0) {

						if (cc->used) {
							memprintf(err, "%sCan't load '%s'. Using crt-store keyword is not compatible with multi certificates bundle.\n",
									err && *err ? *err : "", crt_path);
							cfgerr |= ERR_ALERT | ERR_FATAL;
						}
						ckchs = ckch_store_new_load_files_path(fp, err);
						if (!ckchs) {
							cfgerr |= ERR_ALERT | ERR_FATAL;
							goto error;
						}
					} else {
						continue; /* didn't find this extension, skip */
					}
				}
				found++;
				linenum++; /* we duplicate the line for this entry in the bundle */
				if (!entry_dup) { /* if the entry was used, duplicate one */
					linenum++;
					entry_dup = crtlist_entry_dup(entry);
					if (!entry_dup) {
						cfgerr |= ERR_ALERT | ERR_FATAL;
						goto error;
					}
					entry_dup->linenum = linenum;
				}

				entry_dup->node.key = ckchs;
				entry_dup->crtlist = newlist;

				ebpt_insert(&newlist->entries, &entry_dup->node);
				LIST_APPEND(&newlist->ord_entries, &entry_dup->by_crtlist);
				LIST_APPEND(&ckchs->crtlist_entry, &entry_dup->by_ckch_store);

				entry_dup = NULL; /* the entry was used, we need a new one next round */
			}
#if HA_OPENSSL_VERSION_NUMBER < 0x10101000L
			if (found) {
				memprintf(err, "%sCan't load '%s'. Loading a multi certificates bundle requires OpenSSL >= 1.1.1\n",
						err && *err ? *err : "", crt_path);
				cfgerr |= ERR_ALERT | ERR_FATAL;
			}
#endif
		}
		if (!found) {
			memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
					err && *err ? *err : "", crt_path, strerror(errno));
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}

	} else {
		if (ckch_conf_cmp(&ckchs->conf, cc, err) != 0) {
			memprintf(err, "'%s' in crt-list '%s' line %d, is already defined with incompatible parameters:\n %s", crt_path, file, linenum, err ? *err : "");
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		entry->node.key = ckchs;
		entry->crtlist = newlist;

		ebpt_insert(&newlist->entries, &entry->node);
		LIST_APPEND(&newlist->ord_entries, &entry->by_crtlist);
		LIST_APPEND(&ckchs->crtlist_entry, &entry->by_ckch_store);
		found++;
	}
	entry = NULL;

error:
	return cfgerr;

}


/* This function parse a crt-list file and store it in a struct crtlist, each line is a crtlist_entry structure
 * Fill the <crtlist> argument with a pointer to a new crtlist struct
 *
 * This function tries to open and store certificate files.
 */
int crtlist_parse_file(char *file, struct bind_conf *bind_conf, struct proxy *curproxy, struct crtlist **crtlist, char **err)
{
	struct crtlist *newlist;
	struct crtlist_entry *entry = NULL;
	char thisline[CRT_LINESIZE];
	FILE *f;
	int linenum = 0;
	int cfgerr = 0;
	int missing_lf = -1;

	if ((f = fopen(file, "r")) == NULL) {
		memprintf(err, "cannot open file '%s' : %s", file, strerror(errno));
		return ERR_ALERT | ERR_FATAL;
	}

	newlist = crtlist_new(file, 0);
	if (newlist == NULL) {
		memprintf(err, "Not enough memory!");
		cfgerr |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		char *end;
		char *line = thisline;
		char *crt_path;
		char path[MAXPATHLEN+1];
		struct ckch_conf cc = {};

		if (missing_lf != -1) {
			memprintf(err, "parsing [%s:%d]: Stray NUL character at position %d.\n",
			          file, linenum, (missing_lf + 1));
			cfgerr |= ERR_ALERT | ERR_FATAL;
			missing_lf = -1;
			break;
		}

		linenum++;
		end = line + strlen(line);
		if (end-line == sizeof(thisline)-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			memprintf(err, "parsing [%s:%d]: line too long, limit is %d characters",
				  file, linenum, (int)sizeof(thisline)-1);
			cfgerr |= ERR_ALERT | ERR_FATAL;
			break;
		}

		if (*line == '#' || *line == '\n' || *line == '\r')
			continue;

		if (end > line && *(end-1) == '\n') {
			/* kill trailing LF */
			*(end - 1) = 0;
		}
		else {
			/* mark this line as truncated */
			missing_lf = end - line;
		}

		entry = crtlist_entry_new();
		if (entry == NULL) {
			memprintf(err, "Not enough memory!");
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		cfgerr |= crtlist_parse_line(thisline, &crt_path, entry, &cc, file, linenum, 0, err);
		if (cfgerr & ERR_CODE)
			goto error;

		/* empty line */
		if (!crt_path || !*crt_path) {
			crtlist_entry_free(entry);
			entry = NULL;
			continue;
		}

		if (*crt_path != '@' && *crt_path != '/' && global_ssl.crt_base) {
			if ((strlen(global_ssl.crt_base) + 1 + strlen(crt_path)) > sizeof(path) ||
			    snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, crt_path) > sizeof(path)) {
				memprintf(err, "parsing [%s:%d]: '%s' : path too long",
					  file, linenum, crt_path);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			crt_path = path;
		}

		cfgerr |= crtlist_load_crt(crt_path, &cc, newlist, entry, file, linenum, err);
		if (cfgerr & ERR_CODE)
			goto error;

	}

	if (missing_lf != -1) {
		memprintf(err, "parsing [%s:%d]: Missing LF on last line, file might have been truncated at position %d.\n",
		          file, linenum, (missing_lf + 1));
		cfgerr |= ERR_ALERT | ERR_FATAL;
	}

	if (cfgerr & ERR_CODE)
		goto error;

	newlist->linecount = linenum;

	fclose(f);
	*crtlist = newlist;

	return cfgerr;
error:
	crtlist_entry_free(entry);

	/* FIXME: free cc */

	fclose(f);
	crtlist_free(newlist);
	return cfgerr;
}

/* This function reads a directory and stores it in a struct crtlist, each file is a crtlist_entry structure
 * Fill the <crtlist> argument with a pointer to a new crtlist struct
 *
 * This function tries to open and store certificate files.
 */
int crtlist_load_cert_dir(char *path, struct bind_conf *bind_conf, struct crtlist **crtlist, char **err)
{
	struct crtlist *dir;
	struct dirent **de_list;
	int i, n;
	struct stat buf;
	char *end;
	char fp[MAXPATHLEN+1];
	int cfgerr = 0;
	struct ckch_store *ckchs;

	dir = crtlist_new(path, 1);
	if (dir == NULL) {
		memprintf(err, "not enough memory");
		return ERR_ALERT | ERR_FATAL;
	}

	n = scandir(path, &de_list, 0, alphasort);
	if (n < 0) {
		memprintf(err, "%sunable to scan directory '%s' : %s.\n",
			  err && *err ? *err : "", path, strerror(errno));
		cfgerr |= ERR_ALERT | ERR_FATAL;
	}
	else {
		for (i = 0; i < n; i++) {
			struct crtlist_entry *entry;
			struct dirent *de = de_list[i];

			end = strrchr(de->d_name, '.');
			if (end && (de->d_name[0] == '.' ||
			            strcmp(end, ".issuer") == 0 || strcmp(end, ".ocsp") == 0 ||
			            strcmp(end, ".sctl") == 0 || strcmp(end, ".key") == 0))
				goto ignore_entry;

			snprintf(fp, sizeof(fp), "%s/%s", path, de->d_name);
			if (stat(fp, &buf) != 0) {
				memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
					  err && *err ? *err : "", fp, strerror(errno));
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto ignore_entry;
			}
			if (!S_ISREG(buf.st_mode))
				goto ignore_entry;

			entry = crtlist_entry_new();
			if (entry == NULL) {
				memprintf(err, "not enough memory '%s'", fp);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto ignore_entry;
			}

			ckchs = ckchs_lookup(fp);
			if (ckchs == NULL)
				ckchs = ckch_store_new_load_files_path(fp, err);
			if (ckchs == NULL) {
				free(de);
				free(entry);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
			entry->node.key = ckchs;
			entry->crtlist = dir;
			LIST_APPEND(&ckchs->crtlist_entry, &entry->by_ckch_store);
			LIST_APPEND(&dir->ord_entries, &entry->by_crtlist);
			ebpt_insert(&dir->entries, &entry->node);

ignore_entry:
			free(de);
		}
end:
		free(de_list);
	}

	if (cfgerr & ERR_CODE) {
		/* free the dir and entries on error */
		crtlist_free(dir);
	} else {
		*crtlist = dir;
	}
	return cfgerr;

}

/*
 * Take an ssl_bind_conf structure and append the configuration line used to
 * create it in the buffer
 */
static void dump_crtlist_conf(struct buffer *buf, const struct ssl_bind_conf *conf, const struct ckch_conf *cc)
{
	int space = 0;

	if (conf == NULL && cc->used == 0)
		return;

	chunk_appendf(buf, " [");


	if (conf == NULL)
		goto dump_ckch;

	/* first dump all ssl_conf keywords */

#ifdef OPENSSL_NPN_NEGOTIATED
	if (conf->npn_str) {
		int len = conf->npn_len;
		char *ptr = conf->npn_str;
		int comma = 0;

		chunk_appendf(buf, "npn ");
		while (len) {
			unsigned short size;

			size = *ptr;
			ptr++;
			if (comma)
				chunk_memcat(buf, ",", 1);
			chunk_memcat(buf, ptr, size);
			ptr += size;
			len -= size + 1;
			comma = 1;
		}
		chunk_memcat(buf, "", 1); /* finish with a \0 */
		space++;
	}
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (conf->alpn_str) {
		int len = conf->alpn_len;
		char *ptr = conf->alpn_str;
		int comma = 0;

		if (space) chunk_appendf(buf, " ");
		if (len)
			chunk_appendf(buf, "alpn ");
		else
			chunk_appendf(buf, "no-alpn");
		while (len) {
			unsigned short size;

			size = *ptr;
			ptr++;
			if (comma)
				chunk_memcat(buf, ",", 1);
			chunk_memcat(buf, ptr, size);
			ptr += size;
			len -= size + 1;
			comma = 1;
		}
		chunk_memcat(buf, "", 1); /* finish with a \0 */
		space++;
	}
#endif
	/* verify */
	{
		if (conf->verify == SSL_SOCK_VERIFY_NONE) {
			if (space) chunk_appendf(buf, " ");
			chunk_appendf(buf, "verify none");
			space++;
		} else if (conf->verify == SSL_SOCK_VERIFY_OPTIONAL) {
			if (space) chunk_appendf(buf, " ");
			chunk_appendf(buf, "verify optional");
			space++;
		} else if (conf->verify == SSL_SOCK_VERIFY_REQUIRED) {
			if (space) chunk_appendf(buf, " ");
			chunk_appendf(buf, "verify required");
			space++;
		}
	}

	if (conf->no_ca_names) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "no-ca-names");
		space++;
	}

	if (conf->early_data) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "allow-0rtt");
		space++;
	}
	if (conf->ca_file) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ca-file %s", conf->ca_file);
		space++;
	}
	if (conf->crl_file) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "crl-file %s", conf->crl_file);
		space++;
	}
	if (conf->ciphers) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ciphers %s", conf->ciphers);
		space++;
	}
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (conf->ciphersuites) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ciphersuites %s", conf->ciphersuites);
		space++;
	}
#endif
	if (conf->curves) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "curves %s", conf->curves);
		space++;
	}
	if (conf->ecdhe) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ecdhe %s", conf->ecdhe);
		space++;
	}

	if (conf->client_sigalgs) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "client-sigalgs %s", conf->client_sigalgs);
		space++;
	}

	if (conf->sigalgs) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "sigalgs %s", conf->sigalgs);
		space++;
	}

	/* the crt-lists only support ssl-min-ver and ssl-max-ver */
	if (conf->ssl_methods_cfg.min) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ssl-min-ver %s", methodVersions[conf->ssl_methods_cfg.min].name);
		space++;
	}

	if (conf->ssl_methods_cfg.max) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ssl-max-ver %s", methodVersions[conf->ssl_methods_cfg.max].name);
		space++;
	}

	/* then dump the ckch_conf */
dump_ckch:
	if (!cc->used)
		goto end;

	if (cc->ocsp_update_mode == SSL_SOCK_OCSP_UPDATE_OFF) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ocsp-update off");
		space++;
	} else if (cc->ocsp_update_mode == SSL_SOCK_OCSP_UPDATE_ON) {
		if (space) chunk_appendf(buf, " ");
		chunk_appendf(buf, "ocsp-update on");
		space++;
	}

end:

	chunk_appendf(buf, "]");

	return;
}

/* dump a list of filters */
static void dump_crtlist_filters(struct buffer *buf, struct crtlist_entry *entry)
{
	int i;

	if (!entry->fcount)
		return;

	for (i = 0; i < entry->fcount; i++) {
		chunk_appendf(buf, " %s", entry->filters[i]);
	}
	return;
}

/************************** CLI functions ****************************/


/* CLI IO handler for '(show|dump) ssl crt-list'.
 * It uses show_crtlist_ctx for the context.
 */
static int cli_io_handler_dump_crtlist(struct appctx *appctx)
{
	struct show_crtlist_ctx *ctx = appctx->svcctx;
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *lnode;

	if (trash == NULL)
		return 1;

	/* dump the list of crt-lists */
	lnode = ctx->crtlist_node;
	if (lnode == NULL)
		lnode = ebmb_first(&crtlists_tree);
	while (lnode) {
		chunk_appendf(trash, "%s\n", lnode->key);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
		lnode = ebmb_next(lnode);
	}
	free_trash_chunk(trash);
	return 1;
yield:
	ctx->crtlist_node = lnode;
	free_trash_chunk(trash);
	return 0;
}

/* CLI IO handler for '(show|dump) ssl crt-list <filename>' */
static int cli_io_handler_dump_crtlist_entries(struct appctx *appctx)
{
	struct show_crtlist_ctx *ctx = appctx->svcctx;
	struct buffer *trash = alloc_trash_chunk();
	struct crtlist *crtlist;
	struct crtlist_entry *entry;

	if (trash == NULL)
		return 1;

	crtlist = ebmb_entry(ctx->crtlist_node, struct crtlist, node);

	entry = ctx->entry;
	if (entry == NULL) {
		entry = LIST_ELEM((crtlist->ord_entries).n, typeof(entry), by_crtlist);
		chunk_appendf(trash, "# %s\n", crtlist->node.key);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
	}

	list_for_each_entry_from(entry, &crtlist->ord_entries, by_crtlist) {
		struct ckch_store *store;
		const char *filename;

		store = entry->node.key;
		filename = store->path;
		chunk_appendf(trash, "%s", filename);
		if (ctx->mode == 's') /* show */
			chunk_appendf(trash, ":%d", entry->linenum);
		dump_crtlist_conf(trash, entry->ssl_conf, &store->conf);
		dump_crtlist_filters(trash, entry);
		chunk_appendf(trash, "\n");

		if (applet_putchk(appctx, trash) == -1)
			goto yield;
	}
	free_trash_chunk(trash);
	return 1;
yield:
	ctx->entry = entry;
	free_trash_chunk(trash);
	return 0;
}

/* CLI argument parser for '(show|dump) ssl crt-list' */
static int cli_parse_dump_crtlist(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_crtlist_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct ebmb_node *lnode;
	char *filename = NULL;
	int mode;
	char *end;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (*args[3] && strcmp(args[3], "-n") == 0) {
		mode = 's';
		filename = args[4];
	} else {
		mode = 'd';
		filename = args[3];
	}

	if (mode == 's' && !*args[4])
		return cli_err(appctx, "'show ssl crt-list -n' expects a filename or a directory\n");

	if (filename && *filename) {


		/* strip trailing slashes, including first one */
		for (end = filename + strlen(filename) - 1; end >= filename && *end == '/'; end--)
			*end = 0;

		lnode = ebst_lookup(&crtlists_tree, filename);
		if (lnode == NULL)
			return cli_err(appctx, "didn't find the specified filename\n");

		ctx->crtlist_node = lnode;
		appctx->cli_ctx.io_handler = cli_io_handler_dump_crtlist_entries;
	}
	ctx->mode = mode;

	return 0;
}

/* release function of the  "add ssl crt-list' command, free things and unlock
 * the spinlock. It uses the add_crtlist_ctx.
 */
static void cli_release_add_crtlist(struct appctx *appctx)
{
	struct add_crtlist_ctx *ctx = appctx->svcctx;
	struct crtlist_entry *entry = ctx->entry;

	if (entry) {
		struct ckch_inst *inst, *inst_s;

		/* upon error free the ckch_inst and everything inside */
		ebpt_delete(&entry->node);
		LIST_DELETE(&entry->by_crtlist);
		LIST_DELETE(&entry->by_ckch_store);

		list_for_each_entry_safe(inst, inst_s, &entry->ckch_inst, by_ckchs) {
			ckch_inst_free(inst);
		}
		crtlist_free_filters(entry->filters);
		ssl_sock_free_ssl_conf(entry->ssl_conf);
		free(entry->ssl_conf);
		free(entry);
	}
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	ha_free(&ctx->err);
}


/* IO Handler for the "add ssl crt-list" command It adds a new entry in the
 * crt-list and generates the ckch_insts for each bind_conf that uses this crt-list
 *
 * The logic is the same as the "commit ssl cert" command but without the
 * freeing of the old structures, because there are none.
 *
 * It uses the add_crtlist_ctx for the context.
 */
static int cli_io_handler_add_crtlist(struct appctx *appctx)
{
	struct add_crtlist_ctx *ctx = appctx->svcctx;
	struct bind_conf_list *bind_conf_node;
	struct crtlist *crtlist = ctx->crtlist;
	struct crtlist_entry *entry = ctx->entry;
	struct ckch_store *store = entry->node.key;
	struct ckch_inst *new_inst;
	int i = 0;
	int errcode = 0;

	/* for each bind_conf which use the crt-list, a new ckch_inst must be
	 * created.
	 */
	switch (ctx->state) {
	case ADDCRT_ST_INIT:
		/* This state just print the update message */
		chunk_printf(&trash, "Inserting certificate '%s' in crt-list '%s'", store->path, crtlist->node.key);
		if (applet_putchk(appctx, &trash) == -1)
			goto yield;
		ctx->state = ADDCRT_ST_GEN;
		__fallthrough;
	case ADDCRT_ST_GEN:
		bind_conf_node = ctx->bind_conf_node; /* get the previous ptr from the yield */
		if (bind_conf_node == NULL)
			bind_conf_node = crtlist->bind_conf;
		for (; bind_conf_node; bind_conf_node = bind_conf_node->next) {
			struct bind_conf *bind_conf = bind_conf_node->bind_conf;
			struct sni_ctx *sni;

			ctx->bind_conf_node = bind_conf_node;

			/* yield every 10 generations */
			if (i > 10) {
				applet_have_more_data(appctx); /* let's come back later */
				goto yield;
			}

			/* display one dot for each new instance */
			if (applet_putstr(appctx, ".") == -1)
				goto yield;

			/* we don't support multi-cert bundles, only simple ones */
			ctx->err = NULL;
			errcode |= ckch_inst_new_load_store(store->path, store, bind_conf, entry->ssl_conf, entry->filters, entry->fcount, 0, &new_inst, &ctx->err);
			if (errcode & ERR_CODE) {
				ctx->state = ADDCRT_ST_ERROR;
				goto error;
			}

			/* we need to initialize the SSL_CTX generated */
			/* this iterate on the newly generated SNIs in the new instance to prepare their SSL_CTX */
			list_for_each_entry(sni, &new_inst->sni_ctx, by_ckch_inst) {
				if (!sni->order) { /* we initialized only the first SSL_CTX because it's the same in the other sni_ctx's */
					ctx->err = NULL;
					errcode |= ssl_sock_prep_ctx_and_inst(bind_conf, new_inst->ssl_conf, sni->ctx, sni->ckch_inst, &ctx->err);
					if (errcode & ERR_CODE) {
						ctx->state = ADDCRT_ST_ERROR;
						goto error;
					}
				}
			}

			i++;
			LIST_APPEND(&store->ckch_inst, &new_inst->by_ckchs);
			LIST_APPEND(&entry->ckch_inst, &new_inst->by_crtlist_entry);
			new_inst->crtlist_entry = entry;
		}
		ctx->state = ADDCRT_ST_INSERT;
		__fallthrough;
	case ADDCRT_ST_INSERT:
		/* the insertion is called for every instance of the store, not
		 * only the one we generated.
		 * But the ssl_sock_load_cert_sni() skip the sni already
		 * inserted. Not every instance has a bind_conf, it could be
		 * the store of a server so we should be careful */

		list_for_each_entry(new_inst, &store->ckch_inst, by_ckchs) {
			if (!new_inst->bind_conf) /* this is a server instance */
				continue;
			HA_RWLOCK_WRLOCK(SNI_LOCK, &new_inst->bind_conf->sni_lock);
			ssl_sock_load_cert_sni(new_inst, new_inst->bind_conf);
			HA_RWLOCK_WRUNLOCK(SNI_LOCK, &new_inst->bind_conf->sni_lock);
		}
		entry->linenum = ++crtlist->linecount;
		ctx->entry = NULL;
		ctx->state = ADDCRT_ST_SUCCESS;
		__fallthrough;
	case ADDCRT_ST_SUCCESS:
		chunk_reset(&trash);
		chunk_appendf(&trash, "\n");
		if (ctx->err)
			chunk_appendf(&trash, "%s", ctx->err);
		chunk_appendf(&trash, "Success!\n");
		if (applet_putchk(appctx, &trash) == -1)
			goto yield;
		ctx->state = ADDCRT_ST_FIN;
		break;

	case ADDCRT_ST_ERROR:
	  error:
		chunk_printf(&trash, "\n%sFailed!\n", ctx->err);
		if (applet_putchk(appctx, &trash) == -1)
			goto yield;
		break;

	default:
		break;
	}

end:
	/* success: call the release function and don't come back */
	return 1;
yield:
	return 0; /* should come back */
}


/*
 * Parse a "add ssl crt-list <crt-list> <certfile>" line.
 * Filters and option must be passed through payload.
 * It sets a struct add_crtlist_ctx.
 */
static int cli_parse_add_crtlist(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct add_crtlist_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int cfgerr = 0;
	struct ckch_store *store;
	char *err = NULL;
	char path[MAXPATHLEN+1];
	char *crtlist_path;
	char *cert_path = NULL;
	struct ebmb_node *eb;
	struct ebpt_node *inserted;
	struct crtlist *crtlist;
	struct crtlist_entry *entry = NULL;
	struct ckch_conf cc = {};
	char *end;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || (!payload && !*args[4]))
		return cli_err(appctx, "'add ssl crtlist' expects a filename and a certificate name\n");

	crtlist_path = args[3];

	/* strip trailing slashes, including first one */
	for (end = crtlist_path + strlen(crtlist_path) - 1; end >= crtlist_path && *end == '/'; end--)
		*end = 0;

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Operations on certificates are currently locked!\n");

	eb = ebst_lookup(&crtlists_tree, crtlist_path);
	if (!eb) {
		memprintf(&err, "crt-list '%s' does not exist!", crtlist_path);
		goto error;
	}
	crtlist = ebmb_entry(eb, struct crtlist, node);

	entry = crtlist_entry_new();
	if (entry == NULL) {
		memprintf(&err, "Not enough memory!");
		goto error;
	}


	if (payload) {
		char *lf;

		lf = strrchr(payload, '\n');
		if (lf) {
			memprintf(&err, "only one line of payload is supported!");
			goto error;
		}
		/* cert_path is filled here */
		cfgerr |= crtlist_parse_line(payload, &cert_path, entry, &cc, "CLI", 1, 1, &err);
		if (cfgerr & ERR_CODE)
			goto error;
	} else {
		cert_path = args[4];
	}

	if (!cert_path) {
		memprintf(&err, "'add ssl crtlist' should contain the certificate name in the payload");
		cfgerr |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	if (eb_gettag(crtlist->entries.b[EB_RGHT])) {
		char *slash;

		slash = strrchr(cert_path, '/');
		if (!slash) {
			memprintf(&err, "'%s' is a directory, certificate path '%s' must contain the directory path", (char *)crtlist->node.key, cert_path);
			goto error;
		}
		/* temporary replace / by 0 to do an strcmp */
		*slash = '\0';
		if (strcmp(cert_path, (char*)crtlist->node.key) != 0) {
			*slash = '/';
			memprintf(&err, "'%s' is a directory, certificate path '%s' must contain the directory path", (char *)crtlist->node.key, cert_path);
			goto error;
		}
		*slash = '/';
	}

	if (*cert_path != '@' && *cert_path != '/' && global_ssl.crt_base) {
		if ((strlen(global_ssl.crt_base) + 1 + strlen(cert_path)) > sizeof(path) ||
		    snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, cert_path) > sizeof(path)) {
			memprintf(&err, "'%s' : path too long", cert_path);
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto error;
		}
		cert_path = path;
	}

	store = ckchs_lookup(cert_path);
	if (store == NULL) {
		memprintf(&err, "certificate '%s' does not exist!", cert_path);
		goto error;
	}
	if (store->data == NULL || store->data->cert == NULL) {
		memprintf(&err, "certificate '%s' is empty!", cert_path);
		goto error;
	}

	/* We can use a crt-store keyword when:
	 * - no ckch_inst are linked OR
	 * - ckch_inst are linked but exact same ckch_conf is used.
	 */
	if (LIST_ISEMPTY(&store->ckch_inst)) {

		store->conf = cc;
		/* fresh new, run more init (for example init ocsp-update tasks) */
		cfgerr |= ckch_store_load_files(&cc, store, 1, "CLI", 1, &err);
		if (cfgerr & ERR_FATAL)
			goto error;

	} else if (ckch_conf_cmp(&store->conf, &cc, &err) != 0) {
		memprintf(&err, "'%s' is already instantiated with incompatible parameters:\n %s", cert_path, err ? err : "");
		cfgerr |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	/* check if it's possible to insert this new crtlist_entry */
	entry->node.key = store;
	inserted = ebpt_insert(&crtlist->entries, &entry->node);
	if (inserted != &entry->node) {
		memprintf(&err, "file already exists in this directory!");
		goto error;
	}

	/* this is supposed to be a directory (EB_ROOT_UNIQUE), so no ssl_conf are allowed */
	if ((entry->ssl_conf || entry->filters || cc.used) && eb_gettag(crtlist->entries.b[EB_RGHT])) {
		memprintf(&err, "this is a directory, SSL configuration, crt-store keywords and filters are not allowed");
		goto error;
	}

	LIST_APPEND(&crtlist->ord_entries, &entry->by_crtlist);
	entry->crtlist = crtlist;
	LIST_APPEND(&store->crtlist_entry, &entry->by_ckch_store);

	ctx->state = ADDCRT_ST_INIT;
	ctx->crtlist = crtlist;
	ctx->entry = entry;

	/* unlock is done in the release handler */
	return 0;

error:
	ckch_conf_clean(&cc);
	crtlist_entry_free(entry);
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "Can't edit the crt-list: %s\n", err ? err : "");
	return cli_dynerr(appctx, err);
}

/* Parse a "del ssl crt-list <crt-list> <certfile>" line. */
static int cli_parse_del_crtlist(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct ckch_store *store;
	char *err = NULL;
	char *crtlist_path, *cert_path;
	struct ebmb_node *ebmb;
	struct ebpt_node *ebpt;
	struct crtlist *crtlist;
	struct crtlist_entry *entry = NULL;
	struct ckch_inst *inst, *inst_s;
	int linenum = 0;
	char *colons;
	char *end;
	int error_message_dumped = 0;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || !*args[4])
		return cli_err(appctx, "'del ssl crtlist' expects a filename and a certificate name\n");

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't delete!\nOperations on certificates are currently locked!\n");

	crtlist_path = args[3];
	cert_path = args[4];

	colons = strchr(cert_path, ':');
	if (colons) {
		char *endptr;

		linenum = strtol(colons + 1, &endptr, 10);
		if (colons + 1 == endptr || *endptr != '\0') {
			memprintf(&err, "wrong line number after colons in '%s'!", cert_path);
			goto error;
		}
		*colons = '\0';
	}

	/* strip trailing slashes, including first one */
	for (end = crtlist_path + strlen(crtlist_path) - 1; end >= crtlist_path && *end == '/'; end--)
		*end = 0;

	/* look for crtlist */
	ebmb = ebst_lookup(&crtlists_tree, crtlist_path);
	if (!ebmb) {
		memprintf(&err, "crt-list '%s' does not exist!", crtlist_path);
		goto error;
	}
	crtlist = ebmb_entry(ebmb, struct crtlist, node);

	/* look for store */
	store = ckchs_lookup(cert_path);
	if (store == NULL) {
		memprintf(&err, "certificate '%s' does not exist!", cert_path);
		goto error;
	}
	if (store->data == NULL || store->data->cert == NULL) {
		memprintf(&err, "certificate '%s' is empty!", cert_path);
		goto error;
	}

	ebpt = ebpt_lookup(&crtlist->entries, store);
	if (!ebpt) {
		memprintf(&err, "certificate '%s' can't be found in crt-list '%s'!", cert_path, crtlist_path);
		goto error;
	}

	/* list the line number of entries for errors in err, and select the right ebpt */
	for (; ebpt; ebpt = ebpt_next_dup(ebpt)) {
		struct crtlist_entry *tmp;

		tmp = ebpt_entry(ebpt, struct crtlist_entry, node);
		memprintf(&err, "%s%s%d", err ? err : "", err ? ", " : "", tmp->linenum);

		/* select the entry we wanted */
		if (linenum == 0 || tmp->linenum == linenum) {
			if (!entry)
				entry = tmp;
		}
	}

	/* we didn't found the specified entry */
	if (!entry) {
		memprintf(&err, "found a certificate '%s' but the line number is incorrect, please specify a correct line number preceded by colons (%s)!", cert_path, err ? err : NULL);
		goto error;
	}

	/* we didn't specified a line number but there were several entries */
	if (linenum == 0 && ebpt_next_dup(&entry->node)) {
		memprintf(&err, "found the certificate '%s' in several entries, please specify a line number preceded by colons (%s)!", cert_path, err ? err : NULL);
		goto error;
	}

	/* Iterate over all the instances in order to see if any of them is a
	 * default instance. If this is the case, the entry won't be suppressed. */
	list_for_each_entry_safe(inst, inst_s, &entry->ckch_inst, by_crtlist_entry) {
		if (inst->is_default && !(inst->bind_conf->ssl_options & BC_SSL_O_STRICT_SNI)) {
			if (!error_message_dumped) {
				memprintf(&err, "certificate '%s' cannot be deleted, it is used as default certificate by the following frontends:\n", cert_path);
				error_message_dumped = 1;
			}
			memprintf(&err, "%s\t- %s:%d\n", err, inst->bind_conf->file, inst->bind_conf->line);
		}
	}
	if (error_message_dumped)
		goto error;

	/* upon error free the ckch_inst and everything inside */

	ebpt_delete(&entry->node);
	LIST_DELETE(&entry->by_crtlist);
	LIST_DELETE(&entry->by_ckch_store);

	list_for_each_entry_safe(inst, inst_s, &entry->ckch_inst, by_crtlist_entry) {
		struct sni_ctx *sni, *sni_s;

		HA_RWLOCK_WRLOCK(SNI_LOCK, &inst->bind_conf->sni_lock);
		list_for_each_entry_safe(sni, sni_s, &inst->sni_ctx, by_ckch_inst) {
			ebmb_delete(&sni->name);
			LIST_DELETE(&sni->by_ckch_inst);
			SSL_CTX_free(sni->ctx);
			free(sni);
		}
		HA_RWLOCK_WRUNLOCK(SNI_LOCK, &inst->bind_conf->sni_lock);
		ckch_inst_free(inst);
	}

	crtlist_free_filters(entry->filters);
	ssl_sock_free_ssl_conf(entry->ssl_conf);
	free(entry->ssl_conf);
	free(entry);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "Entry '%s' deleted in crtlist '%s'!\n", cert_path, crtlist_path);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "Can't delete the entry: %s\n", err ? err : "");
	return cli_dynerr(appctx, err);
}


/* unlink and free all crt-list and crt-list entries */
void crtlist_deinit()
{
	struct eb_node *node, *next;
	struct crtlist *crtlist;

	node = eb_first(&crtlists_tree);
	while (node) {
		next = eb_next(node);
		crtlist = ebmb_entry(node, struct crtlist, node);
		crtlist_free(crtlist);
		node = next;
	}
}


/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "add", "ssl", "crt-list", NULL }, "add ssl crt-list <list> <cert> [opts]*  : add to crt-list file <list> a line <cert> or a payload",               cli_parse_add_crtlist, cli_io_handler_add_crtlist, cli_release_add_crtlist },
	{ { "del", "ssl", "crt-list", NULL }, "del ssl crt-list <list> <cert[:line]>   : delete a line <cert> from crt-list file <list>",                       cli_parse_del_crtlist, NULL, NULL },
	{ { "show", "ssl", "crt-list", NULL }, "show ssl crt-list [-n] [<list>]         : show the list of crt-lists or the content of a crt-list file <list>", cli_parse_dump_crtlist, cli_io_handler_dump_crtlist, NULL },
	{ { NULL }, NULL, NULL, NULL } }
};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
