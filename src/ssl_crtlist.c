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

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/errors.h>
#include <common/standard.h>

#include <dirent.h>
#include <ebpttree.h>

#include <types/ssl_crtlist.h>
#include <types/ssl_ckch.h>
#include <types/ssl_sock.h>

#include <proto/ssl_crtlist.h>
#include <proto/ssl_ckch.h>
#include <proto/ssl_sock.h>

/* release ssl bind conf */
void ssl_sock_free_ssl_conf(struct ssl_bind_conf *conf)
{
	if (conf) {
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
		free(conf->npn_str);
		conf->npn_str = NULL;
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		free(conf->alpn_str);
		conf->alpn_str = NULL;
#endif
		free(conf->ca_file);
		conf->ca_file = NULL;
		free(conf->ca_verify_file);
		conf->ca_verify_file = NULL;
		free(conf->crl_file);
		conf->crl_file = NULL;
		free(conf->ciphers);
		conf->ciphers = NULL;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		free(conf->ciphersuites);
		conf->ciphersuites = NULL;
#endif
		free(conf->curves);
		conf->curves = NULL;
		free(conf->ecdhe);
		conf->ecdhe = NULL;
	}
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
	LIST_DEL(&entry->by_crtlist);
	LIST_DEL(&entry->by_ckch_store);
	crtlist_free_filters(entry->filters);
	ssl_sock_free_ssl_conf(entry->ssl_conf);
	free(entry->ssl_conf);
	list_for_each_entry_safe(inst, inst_s, &entry->ckch_inst, by_crtlist_entry) {
		ckch_inst_free(inst);
	}
	free(entry);
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

	/* initialize the nodes so we can LIST_DEL in any cases */
	LIST_INIT(&entry->by_crtlist);
	LIST_INIT(&entry->by_ckch_store);

	return entry;
}

/* Free a crtlist, from the crt_entry to the content of the ssl_conf */
void crtlist_free(struct crtlist *crtlist)
{
	struct crtlist_entry *entry, *s_entry;

	if (crtlist == NULL)
		return;

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
int crtlist_parse_line(char *line, char **crt_path, struct crtlist_entry *entry, const char *file, int linenum, char **err)
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
		memprintf(err, "line %d too long in file '%s', limit is %d characters",
		          linenum, file, CRT_LINESIZE-1);
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
				memprintf(err, "too many '[' on line %d in file '%s'.", linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			if (!arg) {
				memprintf(err, "file must start with a cert on line %d in file '%s'", linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			ssl_b = arg;
			newarg = 1;
			*line = 0;
		} else if (*line == ']') {
			if (ssl_e) {
				memprintf(err, "too many ']' on line %d in file '%s'.", linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			if (!ssl_b) {
				memprintf(err, "missing '[' in line %d in file '%s'.", linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			ssl_e = arg;
			newarg = 1;
			*line = 0;
		} else if (newarg) {
			if (arg == MAX_CRT_ARGS) {
				memprintf(err, "too many args on line %d in file '%s'.", linenum, file);
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
		ssl_conf = calloc(1, sizeof *ssl_conf);
		if (!ssl_conf) {
			memprintf(err, "not enough memory!");
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto error;
		}
	}
	cur_arg = ssl_b ? ssl_b : 1;
	while (cur_arg < ssl_e) {
		newarg = 0;
		for (i = 0; ssl_bind_kws[i].kw != NULL; i++) {
			if (strcmp(ssl_bind_kws[i].kw, args[cur_arg]) == 0) {
				newarg = 1;
				cfgerr |= ssl_bind_kws[i].parse(args, cur_arg, NULL, ssl_conf, err);
				if (cur_arg + 1 + ssl_bind_kws[i].skip > ssl_e) {
					memprintf(err, "ssl args out of '[]' for %s on line %d in file '%s'",
					          args[cur_arg], linenum, file);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					goto error;
				}
				cur_arg += 1 + ssl_bind_kws[i].skip;
				break;
			}
		}
		if (!cfgerr && !newarg) {
			memprintf(err, "unknown ssl keyword %s on line %d in file '%s'.",
				  args[cur_arg], linenum, file);
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
	free(entry->ssl_conf);
	entry->ssl_conf = NULL;
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
	char path[MAXPATHLEN+1];
	FILE *f;
	struct stat buf;
	int linenum = 0;
	int cfgerr = 0;

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
		struct ckch_store *ckchs;

		linenum++;
		end = line + strlen(line);
		if (end-line == sizeof(thisline)-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			memprintf(err, "line %d too long in file '%s', limit is %d characters",
				  linenum, file, (int)sizeof(thisline)-1);
			cfgerr |= ERR_ALERT | ERR_FATAL;
			break;
		}

		if (*line == '#' || *line == '\n' || *line == '\r')
			continue;

		entry = crtlist_entry_new();
		if (entry == NULL) {
			memprintf(err, "Not enough memory!");
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		*(end - 1) = '\0'; /* line parser mustn't receive any \n */
		cfgerr |= crtlist_parse_line(thisline, &crt_path, entry, file, linenum, err);
		if (cfgerr)
			goto error;

		/* empty line */
		if (!crt_path || !*crt_path) {
			crtlist_entry_free(entry);
			entry = NULL;
			continue;
		}

		if (*crt_path != '/' && global_ssl.crt_base) {
			if ((strlen(global_ssl.crt_base) + 1 + strlen(crt_path)) > MAXPATHLEN) {
				memprintf(err, "'%s' : path too long on line %d in file '%s'",
					  crt_path, linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
			snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, crt_path);
			crt_path = path;
		}

		/* Look for a ckch_store or create one */
		ckchs = ckchs_lookup(crt_path);
		if (ckchs == NULL) {
			if (stat(crt_path, &buf) == 0)
				ckchs = ckchs_load_cert_file(crt_path, 0,  err);
			else
				ckchs = ckchs_load_cert_file(crt_path, 1,  err);
		}
		if (ckchs == NULL)
			cfgerr |= ERR_ALERT | ERR_FATAL;

		if (cfgerr & ERR_CODE)
			goto error;

		entry->node.key = ckchs;
		entry->crtlist = newlist;
		ebpt_insert(&newlist->entries, &entry->node);
		LIST_ADDQ(&newlist->ord_entries, &entry->by_crtlist);
		LIST_ADDQ(&ckchs->crtlist_entry, &entry->by_ckch_store);

		entry = NULL;
	}
	if (cfgerr & ERR_CODE)
		goto error;

	newlist->linecount = linenum;

	fclose(f);
	*crtlist = newlist;

	return cfgerr;
error:
	crtlist_entry_free(entry);

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
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
	int is_bundle;
	int j;
#endif

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
			if (end && (!strcmp(end, ".issuer") || !strcmp(end, ".ocsp") || !strcmp(end, ".sctl") || !strcmp(end, ".key")))
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

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
			is_bundle = 0;
			/* Check if current entry in directory is part of a multi-cert bundle */

			if ((global_ssl.extra_files & SSL_GF_BUNDLE) && end) {
				for (j = 0; j < SSL_SOCK_NUM_KEYTYPES; j++) {
					if (!strcmp(end + 1, SSL_SOCK_KEYTYPE_NAMES[j])) {
						is_bundle = 1;
						break;
					}
				}

				if (is_bundle) {
					int dp_len;

					dp_len = end - de->d_name;

					/* increment i and free de until we get to a non-bundle cert
					 * Note here that we look at de_list[i + 1] before freeing de
					 * this is important since ignore_entry will free de. This also
					 * guarantees that de->d_name continues to hold the same prefix.
					 */
					while (i + 1 < n && !strncmp(de_list[i + 1]->d_name, de->d_name, dp_len)) {
						free(de);
						i++;
						de = de_list[i];
					}

					snprintf(fp, sizeof(fp), "%s/%.*s", path, dp_len, de->d_name);
					ckchs = ckchs_lookup(fp);
					if (ckchs == NULL)
						ckchs = ckchs_load_cert_file(fp, 1,  err);
					if (ckchs == NULL) {
						free(de);
						free(entry);
						cfgerr |= ERR_ALERT | ERR_FATAL;
						goto end;
					}
					entry->node.key = ckchs;
					entry->crtlist = dir;
					LIST_ADDQ(&ckchs->crtlist_entry, &entry->by_ckch_store);
					LIST_ADDQ(&dir->ord_entries, &entry->by_crtlist);
					ebpt_insert(&dir->entries, &entry->node);

					/* Successfully processed the bundle */
					goto ignore_entry;
				}
			}

#endif
			ckchs = ckchs_lookup(fp);
			if (ckchs == NULL)
				ckchs = ckchs_load_cert_file(fp, 0,  err);
			if (ckchs == NULL) {
				free(de);
				free(entry);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
			entry->node.key = ckchs;
			entry->crtlist = dir;
			LIST_ADDQ(&ckchs->crtlist_entry, &entry->by_ckch_store);
			LIST_ADDQ(&dir->ord_entries, &entry->by_crtlist);
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

