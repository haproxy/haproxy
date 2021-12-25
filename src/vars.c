#include <ctype.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/global.h>
#include <haproxy/http.h>
#include <haproxy/http_rules.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/sample.h>
#include <haproxy/session.h>
#include <haproxy/stream-t.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tcpcheck.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>
#include <haproxy/xxhash.h>


/* This contains a pool of struct vars */
DECLARE_STATIC_POOL(var_pool, "vars", sizeof(struct var));

/* list of variables for the process scope. */
struct vars proc_vars THREAD_ALIGNED(64);

/* This array of int contains the system limits per context. */
static unsigned int var_global_limit = 0;
static unsigned int var_proc_limit = 0;
static unsigned int var_sess_limit = 0;
static unsigned int var_txn_limit = 0;
static unsigned int var_reqres_limit = 0;
static unsigned int var_check_limit = 0;
static uint64_t var_name_hash_seed = 0;

/* Structure and array matching set-var conditions to their respective flag
 * value.
 */
struct var_set_condition {
       const char *cond_str;
       uint flag;
};

static struct var_set_condition conditions_array[] = {
       { "ifexists", VF_COND_IFEXISTS },
       { "ifnotexists", VF_COND_IFNOTEXISTS },
       { "ifempty", VF_COND_IFEMPTY },
       { "ifnotempty", VF_COND_IFNOTEMPTY },
       { "ifset", VF_COND_IFSET },
       { "ifnotset", VF_COND_IFNOTSET },
       { "ifgt", VF_COND_IFGT },
       { "iflt", VF_COND_IFLT },
       { NULL, 0 }
};

/* returns the struct vars pointer for a session, stream and scope, or NULL if
 * it does not exist.
 */
static inline struct vars *get_vars(struct session *sess, struct stream *strm, enum vars_scope scope)
{
	switch (scope) {
	case SCOPE_PROC:
		return &proc_vars;
	case SCOPE_SESS:
		return sess ? &sess->vars : NULL;
	case SCOPE_CHECK: {
			struct check *check = sess ? objt_check(sess->origin) : NULL;

			return check ? &check->vars : NULL;
		}
	case SCOPE_TXN:
		return strm ? &strm->vars_txn : NULL;
	case SCOPE_REQ:
	case SCOPE_RES:
	default:
		return strm ? &strm->vars_reqres : NULL;
	}
}

/* This function adds or remove memory size from the accounting. The inner
 * pointers may be null when setting the outer ones only.
 */
void var_accounting_diff(struct vars *vars, struct session *sess, struct stream *strm, int size)
{
	switch (vars->scope) {
	case SCOPE_REQ:
	case SCOPE_RES:
		if (var_reqres_limit && strm)
			_HA_ATOMIC_ADD(&strm->vars_reqres.size, size);
		/* fall through */
	case SCOPE_TXN:
		if (var_txn_limit && strm)
			_HA_ATOMIC_ADD(&strm->vars_txn.size, size);
		goto scope_sess;
	case SCOPE_CHECK:
		if (var_check_limit) {
			struct check *check = objt_check(sess->origin);

			if (check)
				_HA_ATOMIC_ADD(&check->vars.size, size);
		}
		/* fall through */
scope_sess:
	case SCOPE_SESS:
		if (var_sess_limit)
			_HA_ATOMIC_ADD(&sess->vars.size, size);
		/* fall through */
	case SCOPE_PROC:
		if (var_proc_limit || var_global_limit)
			_HA_ATOMIC_ADD(&proc_vars.size, size);
	}
}

/* This function returns 1 if the <size> is available in the var
 * pool <vars>, otherwise returns 0. If the space is available,
 * the size is reserved. The inner pointers may be null when setting
 * the outer ones only. The accounting uses either <sess> or <strm>
 * depending on the scope. <strm> may be NULL when no stream is known
 * and only the session exists (eg: tcp-request connection).
 */
static int var_accounting_add(struct vars *vars, struct session *sess, struct stream *strm, int size)
{
	switch (vars->scope) {
	case SCOPE_REQ:
	case SCOPE_RES:
		if (var_reqres_limit && strm && strm->vars_reqres.size + size > var_reqres_limit)
			return 0;
		/* fall through */
	case SCOPE_TXN:
		if (var_txn_limit && strm && strm->vars_txn.size + size > var_txn_limit)
			return 0;
		goto scope_sess;
	case SCOPE_CHECK: {
			struct check *check = objt_check(sess->origin);

			if (var_check_limit && check && check->vars.size + size > var_check_limit)
				return 0;
		}
		/* fall through */
scope_sess:
	case SCOPE_SESS:
		if (var_sess_limit && sess->vars.size + size > var_sess_limit)
			return 0;
		/* fall through */
	case SCOPE_PROC:
		/* note: scope proc collects all others and is currently identical to the
		 * global limit.
		 */
		if (var_proc_limit && proc_vars.size + size > var_proc_limit)
			return 0;
		if (var_global_limit && proc_vars.size + size > var_global_limit)
			return 0;
	}
	var_accounting_diff(vars, sess, strm, size);
	return 1;
}

/* This function removes a variable from the list and frees the memory it was
 * using. If the variable is marked "VF_PERMANENT", the sample_data is only
 * reset to SMP_T_ANY unless <force> is non nul. Returns the freed size.
 */
unsigned int var_clear(struct var *var, int force)
{
	unsigned int size = 0;

	if (var->data.type == SMP_T_STR || var->data.type == SMP_T_BIN) {
		ha_free(&var->data.u.str.area);
		size += var->data.u.str.data;
	}
	else if (var->data.type == SMP_T_METH && var->data.u.meth.meth == HTTP_METH_OTHER) {
		ha_free(&var->data.u.meth.str.area);
		size += var->data.u.meth.str.data;
	}
	/* wipe the sample */
	var->data.type = SMP_T_ANY;

	if (!(var->flags & VF_PERMANENT) || force) {
		LIST_DELETE(&var->l);
		pool_free(var_pool, var);
		size += sizeof(struct var);
	}
	return size;
}

/* This function free all the memory used by all the variables
 * in the list.
 */
void vars_prune(struct vars *vars, struct session *sess, struct stream *strm)
{
	struct var *var, *tmp;
	unsigned int size = 0;

	vars_wrlock(vars);
	list_for_each_entry_safe(var, tmp, &vars->head, l) {
		size += var_clear(var, 1);
	}
	vars_wrunlock(vars);
	var_accounting_diff(vars, sess, strm, -size);
}

/* This function frees all the memory used by all the session variables in the
 * list starting at <vars>.
 */
void vars_prune_per_sess(struct vars *vars)
{
	struct var *var, *tmp;
	unsigned int size = 0;

	vars_wrlock(vars);
	list_for_each_entry_safe(var, tmp, &vars->head, l) {
		size += var_clear(var, 1);
	}
	vars_wrunlock(vars);

	if (var_sess_limit)
		_HA_ATOMIC_SUB(&vars->size, size);
	if (var_proc_limit || var_global_limit)
		_HA_ATOMIC_SUB(&proc_vars.size, size);
}

/* This function initializes a variables list head */
void vars_init_head(struct vars *vars, enum vars_scope scope)
{
	LIST_INIT(&vars->head);
	vars->scope = scope;
	vars->size = 0;
	HA_RWLOCK_INIT(&vars->rwlock);
}

/* This function returns a hash value and a scope for a variable name of a
 * specified length. It makes sure that the scope is valid. It returns non-zero
 * on success, 0 on failure. Neither hash nor scope may be NULL.
 */
static int vars_hash_name(const char *name, int len, enum vars_scope *scope,
                         uint64_t *hash, char **err)
{
	const char *tmp;

	/* Check length. */
	if (len == 0) {
		memprintf(err, "Empty variable name cannot be accepted");
		return 0;
	}

	/* Check scope. */
	if (len > 5 && strncmp(name, "proc.", 5) == 0) {
		name += 5;
		len -= 5;
		*scope = SCOPE_PROC;
	}
	else if (len > 5 && strncmp(name, "sess.", 5) == 0) {
		name += 5;
		len -= 5;
		*scope = SCOPE_SESS;
	}
	else if (len > 4 && strncmp(name, "txn.", 4) == 0) {
		name += 4;
		len -= 4;
		*scope = SCOPE_TXN;
	}
	else if (len > 4 && strncmp(name, "req.", 4) == 0) {
		name += 4;
		len -= 4;
		*scope = SCOPE_REQ;
	}
	else if (len > 4 && strncmp(name, "res.", 4) == 0) {
		name += 4;
		len -= 4;
		*scope = SCOPE_RES;
	}
	else if (len > 6 && strncmp(name, "check.", 6) == 0) {
		name += 6;
		len -= 6;
		*scope = SCOPE_CHECK;
	}
	else {
		memprintf(err, "invalid variable name '%.*s'. A variable name must be start by its scope. "
		               "The scope can be 'proc', 'sess', 'txn', 'req', 'res' or 'check'", len, name);
		return 0;
	}

	/* Check variable name syntax. */
	for (tmp = name; tmp < name + len; tmp++) {
		if (!isalnum((unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
			memprintf(err, "invalid syntax at char '%s'", tmp);
			return 0;
		}
	}

	*hash = XXH3(name, len, var_name_hash_seed);
	return 1;
}

/* This function returns the variable from the given list that matches
 * <name_hash> or returns NULL if not found. It's only a linked list since it
 * is not expected to have many variables per scope (a few tens at best).
 * The caller is responsible for ensuring that <vars> is properly locked.
 */
static struct var *var_get(struct vars *vars, uint64_t name_hash)
{
	struct var *var;

	list_for_each_entry(var, &vars->head, l)
		if (var->name_hash == name_hash)
			return var;
	return NULL;
}

/* Returns 0 if fails, else returns 1. */
static int smp_fetch_var(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const struct var_desc *var_desc = &args[0].data.var;
	const struct buffer *def = NULL;

	if (args[1].type == ARGT_STR)
		def = &args[1].data.str;

	return vars_get_by_desc(var_desc, smp, def);
}

/*
 * Clear the contents of a variable so that it can be reset directly.
 * This function is used just before a variable is filled out of a sample's
 * content.
 */
static inline void var_clear_buffer(struct sample *smp, struct vars *vars, struct var *var, int var_type)
{
       if (var_type == SMP_T_STR || var_type == SMP_T_BIN) {
               ha_free(&var->data.u.str.area);
               var_accounting_diff(vars, smp->sess, smp->strm,
                                   -var->data.u.str.data);
       }
       else if (var_type == SMP_T_METH && var->data.u.meth.meth == HTTP_METH_OTHER) {
               ha_free(&var->data.u.meth.str.area);
               var_accounting_diff(vars, smp->sess, smp->strm,
                                   -var->data.u.meth.str.data);
       }
}

/* This function tries to create a variable whose name hash is <name_hash> in
 * scope <scope> and store sample <smp> as its value.
 *
 * The stream and session are extracted from <smp>, whose stream may be NULL
 * when scope is SCOPE_SESS. In case there wouldn't be enough memory to store
 * the sample while the variable was already created, it would be changed to
 * a bool (which is memory-less).
 *
 * Flags is a bitfield that may contain one of the following flags:
 *   - VF_CREATEONLY: do nothing if the variable already exists (success).
 *   - VF_PERMANENT: this flag will be passed to the variable upon creation
 *
 *   - VF_COND_IFEXISTS: only set variable if it already exists
 *   - VF_COND_IFNOTEXISTS: only set variable if it did not exist yet
 *   - VF_COND_IFEMPTY: only set variable if sample is empty
 *   - VF_COND_IFNOTEMPTY: only set variable if sample is not empty
 *   - VF_COND_IFSET: only set variable if its type is not SMP_TYPE_ANY
 *   - VF_COND_IFNOTSET: only set variable if its type is ANY
 *   - VF_COND_IFGT: only set variable if its value is greater than the sample's
 *   - VF_COND_IFLT: only set variable if its value is less than the sample's
 *
 * It returns 0 on failure, non-zero on success.
 */
static int var_set(uint64_t name_hash, enum vars_scope scope, struct sample *smp, uint flags)
{
	struct vars *vars;
	struct var *var;
	int ret = 0;
	int previous_type = SMP_T_ANY;

	vars = get_vars(smp->sess, smp->strm, scope);
	if (!vars || vars->scope != scope)
		return 0;

	vars_wrlock(vars);

	/* Look for existing variable name. */
	var = var_get(vars, name_hash);

	if (var) {
		if (flags & VF_CREATEONLY) {
			ret = 1;
			goto unlock;
		}

		if (flags & VF_COND_IFNOTEXISTS)
			goto unlock;
	} else {
		if (flags & VF_COND_IFEXISTS)
			goto unlock;

		/* Check memory available. */
		if (!var_accounting_add(vars, smp->sess, smp->strm, sizeof(struct var)))
			goto unlock;

		/* Create new entry. */
		var = pool_alloc(var_pool);
		if (!var)
			goto unlock;
		LIST_APPEND(&vars->head, &var->l);
		var->name_hash = name_hash;
		var->flags = flags & VF_PERMANENT;
		var->data.type = SMP_T_ANY;
	}

	/* A variable of type SMP_T_ANY is considered as unset (either created
	 * and never set or unset-var was called on it).
	 */
	if ((flags & VF_COND_IFSET && var->data.type == SMP_T_ANY) ||
	    (flags & VF_COND_IFNOTSET && var->data.type != SMP_T_ANY))
		goto unlock;

	/* Set type. */
	previous_type = var->data.type;
	var->data.type = smp->data.type;

	if (flags & VF_COND_IFEMPTY) {
		switch(smp->data.type) {
		case SMP_T_ANY:
		case SMP_T_STR:
		case SMP_T_BIN:
			/* The actual test on the contents of the sample will be
			 * performed later.
			 */
			break;
		default:
			/* The sample cannot be empty since it has a scalar type. */
			var->data.type = previous_type;
			goto unlock;
		}
	}

	/* Copy data. If the data needs memory, the function can fail. */
	switch (var->data.type) {
	case SMP_T_BOOL:
		var_clear_buffer(smp, vars, var, previous_type);
		var->data.u.sint = smp->data.u.sint;
		break;
	case SMP_T_SINT:
		if (previous_type == var->data.type) {
			if (((flags & VF_COND_IFGT) && !(var->data.u.sint > smp->data.u.sint)) ||
			    ((flags & VF_COND_IFLT) && !(var->data.u.sint < smp->data.u.sint)))
				goto unlock;
		}
		var_clear_buffer(smp, vars, var, previous_type);
		var->data.u.sint = smp->data.u.sint;
		break;
	case SMP_T_IPV4:
		var_clear_buffer(smp, vars, var, previous_type);
		var->data.u.ipv4 = smp->data.u.ipv4;
		break;
	case SMP_T_IPV6:
		var_clear_buffer(smp, vars, var, previous_type);
		var->data.u.ipv6 = smp->data.u.ipv6;
		break;
	case SMP_T_STR:
	case SMP_T_BIN:
		if ((flags & VF_COND_IFNOTEMPTY && !smp->data.u.str.data) ||
		    (flags & VF_COND_IFEMPTY && smp->data.u.str.data)) {
			var->data.type = previous_type;
			goto unlock;
		}
		var_clear_buffer(smp, vars, var, previous_type);
		if (!var_accounting_add(vars, smp->sess, smp->strm, smp->data.u.str.data)) {
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			goto unlock;
		}

		var->data.u.str.area = malloc(smp->data.u.str.data);
		if (!var->data.u.str.area) {
			var_accounting_diff(vars, smp->sess, smp->strm,
					    -smp->data.u.str.data);
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			goto unlock;
		}
		var->data.u.str.data = smp->data.u.str.data;
		memcpy(var->data.u.str.area, smp->data.u.str.area,
		       var->data.u.str.data);
		break;
	case SMP_T_METH:
		var_clear_buffer(smp, vars, var, previous_type);
		var->data.u.meth.meth = smp->data.u.meth.meth;
		if (smp->data.u.meth.meth != HTTP_METH_OTHER)
			break;

		if (!var_accounting_add(vars, smp->sess, smp->strm, smp->data.u.meth.str.data)) {
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			goto unlock;
		}

		var->data.u.meth.str.area = malloc(smp->data.u.meth.str.data);
		if (!var->data.u.meth.str.area) {
			var_accounting_diff(vars, smp->sess, smp->strm,
					    -smp->data.u.meth.str.data);
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			goto unlock;
		}
		var->data.u.meth.str.data = smp->data.u.meth.str.data;
		var->data.u.meth.str.size = smp->data.u.meth.str.data;
		memcpy(var->data.u.meth.str.area, smp->data.u.meth.str.area,
		       var->data.u.meth.str.data);
		break;
	}

	/* OK, now done */
	ret = 1;
 unlock:
	vars_wrunlock(vars);
	return ret;
}

/* Deletes a variable matching name hash <name_hash> and scope <scope> for the
 * session and stream found in <smp>. Note that stream may be null for
 * SCOPE_SESS. Returns 0 if the scope was not found otherwise 1.
 */
static int var_unset(uint64_t name_hash, enum vars_scope scope, struct sample *smp)
{
	struct vars *vars;
	struct var  *var;
	unsigned int size = 0;

	vars = get_vars(smp->sess, smp->strm, scope);
	if (!vars || vars->scope != scope)
		return 0;

	/* Look for existing variable name. */
	vars_wrlock(vars);
	var = var_get(vars, name_hash);
	if (var) {
		size = var_clear(var, 0);
		var_accounting_diff(vars, smp->sess, smp->strm, -size);
	}
	vars_wrunlock(vars);
	return 1;
}


/*
 * Convert a string set-var condition into its numerical value.
 * The corresponding bit is set in the <cond_bitmap> parameter if the
 * <cond> is known.
 * Returns 1 in case of success.
 */
static int vars_parse_cond_param(const struct buffer *cond, uint *cond_bitmap, char **err)
{
	struct var_set_condition *cond_elt = &conditions_array[0];

	/* The conditions array is NULL terminated. */
	while (cond_elt->cond_str) {
		if (chunk_strcmp(cond, cond_elt->cond_str) == 0) {
			*cond_bitmap |= cond_elt->flag;
			break;
		}
		++cond_elt;
	}

	if (cond_elt->cond_str == NULL && err)
		memprintf(err, "unknown condition \"%.*s\"", (int)cond->data, cond->area);

	return cond_elt->cond_str != NULL;
}

/* Returns 0 if fails, else returns 1. */
static int smp_conv_store(const struct arg *args, struct sample *smp, void *private)
{
	uint conditions = 0;
	int cond_idx = 1;

	while (args[cond_idx].type == ARGT_STR) {
		if (vars_parse_cond_param(&args[cond_idx++].data.str, &conditions, NULL) == 0)
			break;
	}

	return var_set(args[0].data.var.name_hash, args[0].data.var.scope, smp, conditions);
}

/* Returns 0 if fails, else returns 1. */
static int smp_conv_clear(const struct arg *args, struct sample *smp, void *private)
{
	return var_unset(args[0].data.var.name_hash, args[0].data.var.scope, smp);
}

/* This functions check an argument entry and fill it with a variable
 * type. The argumen must be a string. If the variable lookup fails,
 * the function returns 0 and fill <err>, otherwise it returns 1.
 */
int vars_check_arg(struct arg *arg, char **err)
{
	enum vars_scope scope;
	struct sample empty_smp = { };
	uint64_t hash;

	/* Check arg type. */
	if (arg->type != ARGT_STR) {
		memprintf(err, "unexpected argument type");
		return 0;
	}

	/* Register new variable name. */
	if (!vars_hash_name(arg->data.str.area, arg->data.str.data, &scope, &hash, err))
		return 0;

	if (scope == SCOPE_PROC && !var_set(hash, scope, &empty_smp, VF_CREATEONLY|VF_PERMANENT))
		return 0;

	/* properly destroy the chunk */
	chunk_destroy(&arg->data.str);

	/* Use the global variable name pointer. */
	arg->type = ARGT_VAR;
	arg->data.var.name_hash = hash;
	arg->data.var.scope = scope;
	return 1;
}

/* This function stores a sample in a variable unless it is of type "proc" and
 * not defined yet.
 * Returns zero on failure and non-zero otherwise. The variable not being
 * defined is treated as a failure.
 */
int vars_set_by_name_ifexist(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;
	uint64_t hash;

	/* Resolve name and scope. */
	if (!vars_hash_name(name, len, &scope, &hash, NULL))
		return 0;

	/* Variable creation is allowed for all scopes apart from the PROC one. */
	return var_set(hash, scope, smp, (scope == SCOPE_PROC) ? VF_COND_IFEXISTS : 0);
}


/* This function stores a sample in a variable.
 * Returns zero on failure and non-zero otherwise.
 */
int vars_set_by_name(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;
	uint64_t hash;

	/* Resolve name and scope. */
	if (!vars_hash_name(name, len, &scope, &hash, NULL))
		return 0;

	return var_set(hash, scope, smp, 0);
}

/* This function unsets a variable if it was already defined.
 * Returns zero on failure and non-zero otherwise.
 */
int vars_unset_by_name_ifexist(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;
	uint64_t hash;

	/* Resolve name and scope. */
	if (!vars_hash_name(name, len, &scope, &hash, NULL))
		return 0;

	return var_unset(hash, scope, smp);
}


/* This retrieves variable whose hash matches <name_hash> from variables <vars>,
 * and if found and not empty, duplicates the result into sample <smp>.
 * smp_dup() is used in order to release the variables lock ASAP (so a pre-
 * allocated chunk is obtained via get_trash_shunk()). The variables' lock is
 * used for reads.
 *
 * The function returns 0 if the variable was not found and no default
 * value was provided in <def>, otherwise 1 with the sample filled.
 * Default values are always returned as strings.
 */
static int var_to_smp(struct vars *vars, uint64_t name_hash, struct sample *smp, const struct buffer *def)
{
	struct var *var;

	/* Get the variable entry. */
	vars_rdlock(vars);
	var = var_get(vars, name_hash);
	if (!var || !var->data.type) {
		if (!def) {
			vars_rdunlock(vars);
			return 0;
		}

		/* not found but we have a default value */
		smp->data.type = SMP_T_STR;
		smp->data.u.str = *def;
	}
	else
		smp->data = var->data;

	/* Copy sample. */
	smp_dup(smp);

	vars_rdunlock(vars);
	return 1;
}

/* This function fills a sample with the variable content.
 *
 * Keep in mind that a sample content is duplicated by using smp_dup()
 * and it therefore uses a pre-allocated trash chunk as returned by
 * get_trash_chunk().
 *
 * If the variable is not valid in this scope, 0 is always returned.
 * If the variable is valid but not found, either the default value
 * <def> is returned if not NULL, or zero is returned.
 *
 * Returns 1 if the sample is filled, otherwise it returns 0.
 */
int vars_get_by_name(const char *name, size_t len, struct sample *smp, const struct buffer *def)
{
	struct vars *vars;
	enum vars_scope scope;
	uint64_t hash;

	/* Resolve name and scope. */
	if (!vars_hash_name(name, len, &scope, &hash, NULL))
		return 0;

	/* Select "vars" pool according with the scope. */
	vars = get_vars(smp->sess, smp->strm, scope);
	if (!vars || vars->scope != scope)
		return 0;

	return var_to_smp(vars, hash, smp, def);
}

/* This function fills a sample with the content of the variable described
 * by <var_desc>.
 *
 * Keep in mind that a sample content is duplicated by using smp_dup()
 * and it therefore uses a pre-allocated trash chunk as returned by
 * get_trash_chunk().
 *
 * If the variable is not valid in this scope, 0 is always returned.
 * If the variable is valid but not found, either the default value
 * <def> is returned if not NULL, or zero is returned.
 *
 * Returns 1 if the sample is filled, otherwise it returns 0.
 */
int vars_get_by_desc(const struct var_desc *var_desc, struct sample *smp, const struct buffer *def)
{
	struct vars *vars;

	/* Select "vars" pool according with the scope. */
	vars = get_vars(smp->sess, smp->strm, var_desc->scope);

	/* Check if the scope is available a this point of processing. */
	if (!vars || vars->scope != var_desc->scope)
		return 0;

	return var_to_smp(vars, var_desc->name_hash, smp, def);
}

/* Always returns ACT_RET_CONT even if an error occurs. */
static enum act_return action_store(struct act_rule *rule, struct proxy *px,
                                    struct session *sess, struct stream *s, int flags)
{
	struct buffer *fmtstr = NULL;
	struct sample smp;
	int dir;

	switch (rule->from) {
	case ACT_F_TCP_REQ_CON: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_REQ_SES: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_REQ_CNT: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_RES_CNT: dir = SMP_OPT_DIR_RES; break;
	case ACT_F_HTTP_REQ:    dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_HTTP_RES:    dir = SMP_OPT_DIR_RES; break;
	case ACT_F_TCP_CHK:     dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_CFG_PARSER:  dir = SMP_OPT_DIR_REQ;  break; /* not used anyway */
	case ACT_F_CLI_PARSER:  dir = SMP_OPT_DIR_REQ;  break; /* not used anyway */
	default:
		send_log(px, LOG_ERR, "Vars: internal error while execute action store.");
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			ha_alert("Vars: internal error while execute action store.\n");
		return ACT_RET_CONT;
	}

	/* Process the expression. */
	memset(&smp, 0, sizeof(smp));

	if (!LIST_ISEMPTY(&rule->arg.vars.fmt)) {
		/* a format-string is used */

		fmtstr = alloc_trash_chunk();
		if (!fmtstr) {
			send_log(px, LOG_ERR, "Vars: memory allocation failure while processing store rule.");
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				ha_alert("Vars: memory allocation failure while processing store rule.\n");
			return ACT_RET_CONT;
		}

		/* execute the log-format expression */
		fmtstr->data = sess_build_logline(sess, s, fmtstr->area, fmtstr->size, &rule->arg.vars.fmt);

		/* convert it to a sample of type string as it's what the vars
		 * API consumes, and store it.
		 */
		smp_set_owner(&smp, px, sess, s, 0);
		smp.data.type = SMP_T_STR;
		smp.data.u.str = *fmtstr;
		var_set(rule->arg.vars.name_hash, rule->arg.vars.scope, &smp, rule->arg.vars.conditions);
	}
	else {
		/* an expression is used */
		if (!sample_process(px, sess, s, dir|SMP_OPT_FINAL,
	                            rule->arg.vars.expr, &smp))
			return ACT_RET_CONT;
	}

	/* Store the sample, and ignore errors. */
	var_set(rule->arg.vars.name_hash, rule->arg.vars.scope, &smp, rule->arg.vars.conditions);
	free_trash_chunk(fmtstr);
	return ACT_RET_CONT;
}

/* Always returns ACT_RET_CONT even if an error occurs. */
static enum act_return action_clear(struct act_rule *rule, struct proxy *px,
                                    struct session *sess, struct stream *s, int flags)
{
	struct sample smp;

	memset(&smp, 0, sizeof(smp));
	smp_set_owner(&smp, px, sess, s, SMP_OPT_FINAL);

	/* Clear the variable using the sample context, and ignore errors. */
	var_unset(rule->arg.vars.name_hash, rule->arg.vars.scope, &smp);
	return ACT_RET_CONT;
}

static void release_store_rule(struct act_rule *rule)
{
	struct logformat_node *lf, *lfb;

	list_for_each_entry_safe(lf, lfb, &rule->arg.vars.fmt, list) {
		LIST_DELETE(&lf->list);
		release_sample_expr(lf->expr);
		free(lf->arg);
		free(lf);
	}

	release_sample_expr(rule->arg.vars.expr);
}

/* This two function checks the variable name and replace the
 * configuration string name by the global string name. its
 * the same string, but the global pointer can be easy to
 * compare. They return non-zero on success, zero on failure.
 *
 * The first function checks a sample-fetch and the second
 * checks a converter.
 */
static int smp_check_var(struct arg *args, char **err)
{
	return vars_check_arg(&args[0], err);
}

static int conv_check_var(struct arg *args, struct sample_conv *conv,
                          const char *file, int line, char **err_msg)
{
	int cond_idx = 1;
	uint conditions = 0;
	int retval = vars_check_arg(&args[0], err_msg);

	while (retval && args[cond_idx].type == ARGT_STR)
		retval = vars_parse_cond_param(&args[cond_idx++].data.str, &conditions, err_msg);

	return retval;
}

/* This function is a common parser for using variables. It understands
 * the format:
 *
 *   set-var-fmt(<variable-name>[,<cond> ...]) <format-string>
 *   set-var(<variable-name>[,<cond> ...]) <expression>
 *   unset-var(<variable-name>)
 *
 * It returns ACT_RET_PRS_ERR if fails and <err> is filled with an error
 * message. Otherwise, it returns ACT_RET_PRS_OK and the variable <expr>
 * is filled with the pointer to the expression to execute. The proxy is
 * only used to retrieve the ->conf entries.
 */
static enum act_parse_ret parse_store(const char **args, int *arg, struct proxy *px,
                                      struct act_rule *rule, char **err)
{
	const char *var_name = args[*arg-1];
	int var_len;
	const char *kw_name;
	int flags = 0, set_var = 0; /* 0=unset-var, 1=set-var, 2=set-var-fmt */
	struct sample empty_smp = { };
	struct ist condition = IST_NULL;
	struct ist var = IST_NULL;
	struct ist varname_ist = IST_NULL;

	if (strncmp(var_name, "set-var-fmt", 11) == 0) {
		var_name += 11;
		set_var   = 2;
	}
	else if (strncmp(var_name, "set-var", 7) == 0) {
		var_name += 7;
		set_var   = 1;
	}
	else if (strncmp(var_name, "unset-var", 9) == 0) {
		var_name += 9;
		set_var   = 0;
	}

	if (*var_name != '(') {
		memprintf(err, "invalid or incomplete action '%s'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'",
			  args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}
	var_name++; /* jump the '(' */
	var_len = strlen(var_name);
	var_len--; /* remove the ')' */
	if (var_name[var_len] != ')') {
		memprintf(err, "incomplete argument after action '%s'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'",
			  args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}

	/* Parse the optional conditions. */
	var = ist2(var_name, var_len);
	varname_ist = istsplit(&var, ',');
	var_len = istlen(varname_ist);

	condition = istsplit(&var, ',');

	if (istlen(condition) && set_var == 0) {
		memprintf(err, "unset-var does not expect parameters after the variable name. Only \"set-var\" and \"set-var-fmt\" manage conditions");
		return ACT_RET_PRS_ERR;
	}

	while (istlen(condition)) {
		struct buffer cond = {};

		chunk_initlen(&cond, istptr(condition), 0, istlen(condition));
		if (vars_parse_cond_param(&cond, &rule->arg.vars.conditions, err) == 0)
			return ACT_RET_PRS_ERR;

		condition = istsplit(&var, ',');
	}

	LIST_INIT(&rule->arg.vars.fmt);
	if (!vars_hash_name(var_name, var_len, &rule->arg.vars.scope, &rule->arg.vars.name_hash, err))
		return ACT_RET_PRS_ERR;

	if (rule->arg.vars.scope == SCOPE_PROC &&
	    !var_set(rule->arg.vars.name_hash, rule->arg.vars.scope, &empty_smp, VF_CREATEONLY|VF_PERMANENT))
		return 0;

	/* There is no fetch method when variable is unset. Just set the right
	 * action and return. */
	if (!set_var) {
		rule->action     = ACT_CUSTOM;
		rule->action_ptr = action_clear;
		rule->release_ptr = release_store_rule;
		return ACT_RET_PRS_OK;
	}

	kw_name = args[*arg-1];

	switch (rule->from) {
	case ACT_F_TCP_REQ_CON:
		flags = SMP_VAL_FE_CON_ACC;
		px->conf.args.ctx = ARGC_TCO;
		break;
	case ACT_F_TCP_REQ_SES:
		flags = SMP_VAL_FE_SES_ACC;
		px->conf.args.ctx = ARGC_TSE;
		break;
	case ACT_F_TCP_REQ_CNT:
		if (px->cap & PR_CAP_FE)
			flags |= SMP_VAL_FE_REQ_CNT;
		if (px->cap & PR_CAP_BE)
			flags |= SMP_VAL_BE_REQ_CNT;
		px->conf.args.ctx = ARGC_TRQ;
		break;
	case ACT_F_TCP_RES_CNT:
		if (px->cap & PR_CAP_FE)
			flags |= SMP_VAL_FE_RES_CNT;
		if (px->cap & PR_CAP_BE)
			flags |= SMP_VAL_BE_RES_CNT;
		px->conf.args.ctx = ARGC_TRS;
		break;
	case ACT_F_HTTP_REQ:
		if (px->cap & PR_CAP_FE)
			flags |= SMP_VAL_FE_HRQ_HDR;
		if (px->cap & PR_CAP_BE)
			flags |= SMP_VAL_BE_HRQ_HDR;
		px->conf.args.ctx = ARGC_HRQ;
		break;
	case ACT_F_HTTP_RES:
		if (px->cap & PR_CAP_FE)
			flags |= SMP_VAL_FE_HRS_HDR;
		if (px->cap & PR_CAP_BE)
			flags |= SMP_VAL_BE_HRS_HDR;
		px->conf.args.ctx =  ARGC_HRS;
		break;
	case ACT_F_TCP_CHK:
		flags = SMP_VAL_BE_CHK_RUL;
		px->conf.args.ctx = ARGC_TCK;
		break;
	case ACT_F_CFG_PARSER:
		flags = SMP_VAL_CFG_PARSER;
		px->conf.args.ctx = ARGC_CFG;
		break;
	case ACT_F_CLI_PARSER:
		flags = SMP_VAL_CLI_PARSER;
		px->conf.args.ctx = ARGC_CLI;
		break;
	default:
		memprintf(err,
			  "internal error, unexpected rule->from=%d, please report this bug!",
			  rule->from);
		return ACT_RET_PRS_ERR;
	}

	if (set_var == 2) { /* set-var-fmt */
		if (!parse_logformat_string(args[*arg], px, &rule->arg.vars.fmt, 0, flags, err))
			return ACT_RET_PRS_ERR;

		(*arg)++;

		/* for late error reporting */
		free(px->conf.lfs_file);
		px->conf.lfs_file = strdup(px->conf.args.file);
		px->conf.lfs_line = px->conf.args.line;
	} else {
		/* set-var */
		rule->arg.vars.expr = sample_parse_expr((char **)args, arg, px->conf.args.file,
	                                                px->conf.args.line, err, &px->conf.args, NULL);
		if (!rule->arg.vars.expr)
			return ACT_RET_PRS_ERR;

		if (!(rule->arg.vars.expr->fetch->val & flags)) {
			memprintf(err,
			          "fetch method '%s' extracts information from '%s', none of which is available here",
			          kw_name, sample_src_names(rule->arg.vars.expr->fetch->use));
			free(rule->arg.vars.expr);
			return ACT_RET_PRS_ERR;
		}
	}

	rule->action     = ACT_CUSTOM;
	rule->action_ptr = action_store;
	rule->release_ptr = release_store_rule;
	return ACT_RET_PRS_OK;
}


/* parses a global "set-var" directive. It will create a temporary rule and
 * expression that are parsed, processed, and released on the fly so that we
 * respect the real set-var syntax. These directives take the following format:
 *    set-var <name> <expression>
 *    set-var-fmt <name> <fmt>
 * Note that parse_store() expects "set-var(name) <expression>" so we have to
 * temporarily replace the keyword here.
 */
static int vars_parse_global_set_var(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int line,
                                     char **err)
{
	struct proxy px = {
		.id = "CFG",
		.conf.args.file = file,
		.conf.args.line = line,
	};
	struct act_rule rule = {
		.arg.vars.scope = SCOPE_PROC,
		.from = ACT_F_CFG_PARSER,
		.conf.file = (char *)file,
		.conf.line = line,
	};
	enum obj_type objt = OBJ_TYPE_NONE;
	struct session *sess = NULL;
	enum act_parse_ret p_ret;
	char *old_arg1;
	char *tmp_arg1;
	int arg = 2; // variable name
	int ret = -1;
	int use_fmt = 0;

	LIST_INIT(&px.conf.args.list);

	use_fmt = strcmp(args[0], "set-var-fmt") == 0;

	if (!*args[1] || !*args[2]) {
		if (use_fmt)
			memprintf(err, "'%s' requires a process-wide variable name ('proc.<name>') and a format string.", args[0]);
		else
			memprintf(err, "'%s' requires a process-wide variable name ('proc.<name>') and a sample expression.", args[0]);
		goto end;
	}

	tmp_arg1 = NULL;
	if (!memprintf(&tmp_arg1, "set-var%s(%s)", use_fmt ? "-fmt" : "", args[1]))
		goto end;

	/* parse_store() will always return a message in <err> on error */
	old_arg1 = args[1]; args[1] = tmp_arg1;
	p_ret = parse_store((const char **)args, &arg, &px, &rule, err);
	free(args[1]); args[1] = old_arg1;

	if (p_ret != ACT_RET_PRS_OK)
		goto end;

	if (rule.arg.vars.scope != SCOPE_PROC) {
		memprintf(err, "'%s': cannot set variable '%s', only scope 'proc' is permitted in the global section.", args[0], args[1]);
		goto end;
	}

	if (smp_resolve_args(&px, err) != 0) {
		release_sample_expr(rule.arg.vars.expr);
		indent_msg(err, 2);
		goto end;
	}

	if (use_fmt && !(sess = session_new(&px, NULL, &objt))) {
		release_sample_expr(rule.arg.vars.expr);
		memprintf(err, "'%s': out of memory when trying to set variable '%s' in the global section.", args[0], args[1]);
		goto end;
	}

	action_store(&rule, &px, sess, NULL, 0);
	release_sample_expr(rule.arg.vars.expr);
	if (sess)
		session_free(sess);

	ret = 0;
 end:
	return ret;
}

/* parse CLI's "get var <name>" */
static int vars_parse_cli_get_var(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct vars *vars;
	struct sample smp = { };
	int i;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (!*args[2])
		return cli_err(appctx, "Missing process-wide variable identifier.\n");

	vars = get_vars(NULL, NULL, SCOPE_PROC);
	if (!vars || vars->scope != SCOPE_PROC)
		return 0;

	if (!vars_get_by_name(args[2], strlen(args[2]), &smp, NULL))
		return cli_err(appctx, "Variable not found.\n");

	/* the sample returned by vars_get_by_name() is allocated into a trash
	 * chunk so we have no constraint to manipulate it.
	 */
	chunk_printf(&trash, "%s: type=%s value=", args[2], smp_to_type[smp.data.type]);

	if (!sample_casts[smp.data.type][SMP_T_STR] ||
	    !sample_casts[smp.data.type][SMP_T_STR](&smp)) {
		chunk_appendf(&trash, "(undisplayable)");
	} else {
		/* Display the displayable chars*. */
		b_putchr(&trash, '<');
		for (i = 0; i < smp.data.u.str.data; i++) {
			if (isprint((unsigned char)smp.data.u.str.area[i]))
				b_putchr(&trash, smp.data.u.str.area[i]);
			else
				b_putchr(&trash, '.');
		}
		b_putchr(&trash, '>');
		b_putchr(&trash, 0);
	}
	return cli_msg(appctx, LOG_INFO, trash.area);
}

/* parse CLI's "set var <name>". It accepts:
 *  - set var <name> <expression>
 *  - set var <name> expr <expression>
 *  - set var <name> fmt <format>
 */
static int vars_parse_cli_set_var(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct proxy px = {
		.id = "CLI",
		.conf.args.file = "CLI",
		.conf.args.line = 0,
	};
	struct act_rule rule = {
		.arg.vars.scope = SCOPE_PROC,
		.from = ACT_F_CLI_PARSER,
		.conf.file = "CLI",
		.conf.line = 0,
	};
	enum obj_type objt = OBJ_TYPE_NONE;
	struct session *sess = NULL;
	enum act_parse_ret p_ret;
	const char *tmp_args[3];
	int tmp_arg;
	char *tmp_act;
	char *err = NULL;
	int nberr;
	int use_fmt = 0;

	LIST_INIT(&px.conf.args.list);

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	if (!*args[2])
		return cli_err(appctx, "Missing process-wide variable identifier.\n");

	if (!*args[3])
		return cli_err(appctx, "Missing either 'expr', 'fmt' or expression.\n");

	if (*args[4]) {
		/* this is the long format */
		if (strcmp(args[3], "fmt") == 0)
			use_fmt = 1;
		else if (strcmp(args[3], "expr") != 0) {
			memprintf(&err, "'%s %s': arg type must be either 'expr' or 'fmt' but got '%s'.", args[0], args[1], args[3]);
			goto fail;
		}
	}

	tmp_act = NULL;
	if (!memprintf(&tmp_act, "set-var%s(%s)", use_fmt ? "-fmt" : "", args[2])) {
		memprintf(&err, "memory allocation error.");
		goto fail;
	}

	/* parse_store() will always return a message in <err> on error */
	tmp_args[0] = tmp_act;
	tmp_args[1] = (*args[4]) ? args[4] : args[3];
	tmp_args[2] = "";
	tmp_arg = 1; // must point to the first arg after the action
	p_ret = parse_store(tmp_args, &tmp_arg, &px, &rule, &err);
	free(tmp_act);

	if (p_ret != ACT_RET_PRS_OK)
		goto fail;

	if (rule.arg.vars.scope != SCOPE_PROC) {
		memprintf(&err, "'%s %s': cannot set variable '%s', only scope 'proc' is permitted here.", args[0], args[1], args[2]);
		goto fail;
	}

	err = NULL;
	nberr = smp_resolve_args(&px, &err);
	if (nberr) {
		release_sample_expr(rule.arg.vars.expr);
		indent_msg(&err, 2);
		goto fail;
	}

	if (use_fmt && !(sess = session_new(&px, NULL, &objt))) {
		release_sample_expr(rule.arg.vars.expr);
		memprintf(&err, "memory allocation error.");
		goto fail;
	}

	action_store(&rule, &px, sess, NULL, 0);
	release_sample_expr(rule.arg.vars.expr);
	if (sess)
		session_free(sess);

	appctx->st0 = CLI_ST_PROMPT;
	return 0;
 fail:
	return cli_dynerr(appctx, err);
}

static int vars_max_size(char **args, int section_type, struct proxy *curpx,
                         const struct proxy *defpx, const char *file, int line,
                         char **err, unsigned int *limit)
{
	char *error;

	*limit = strtol(args[1], &error, 10);
	if (*error != 0) {
		memprintf(err, "%s: '%s' is an invalid size", args[0], args[1]);
		return -1;
	}
	return 0;
}

static int vars_max_size_global(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_global_limit);
}

static int vars_max_size_proc(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_proc_limit);
}

static int vars_max_size_sess(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_sess_limit);
}

static int vars_max_size_txn(char **args, int section_type, struct proxy *curpx,
                             const struct proxy *defpx, const char *file, int line,
                             char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_txn_limit);
}

static int vars_max_size_reqres(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_reqres_limit);
}

static int vars_max_size_check(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_check_limit);
}

/* early boot initialization */
static void vars_init()
{
	var_name_hash_seed = ha_random64();
}

INITCALL0(STG_PREPARE, vars_init);

static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {

	{ "var", smp_fetch_var, ARG2(1,STR,STR), smp_check_var, SMP_T_ANY, SMP_USE_CONST },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);

static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "set-var",   smp_conv_store, ARG5(1,STR,STR,STR,STR,STR), conv_check_var, SMP_T_ANY, SMP_T_ANY },
	{ "unset-var", smp_conv_clear, ARG1(1,STR), conv_check_var, SMP_T_ANY, SMP_T_ANY },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);

static struct action_kw_list tcp_req_conn_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_conn_keywords_register, &tcp_req_conn_kws);

static struct action_kw_list tcp_req_sess_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_sess_keywords_register, &tcp_req_sess_kws);

static struct action_kw_list tcp_req_cont_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_cont_kws);

static struct action_kw_list tcp_res_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_kws);

static struct action_kw_list tcp_check_kws = {ILH, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_check_keywords_register, &tcp_check_kws);

static struct action_kw_list http_req_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_kws);

static struct action_kw_list http_res_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_kws);

static struct action_kw_list http_after_res_kws = { { }, {
	{ "set-var-fmt", parse_store, KWF_MATCH_PREFIX },
	{ "set-var",   parse_store, KWF_MATCH_PREFIX },
	{ "unset-var", parse_store, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_after_res_keywords_register, &http_after_res_kws);

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "set-var",              vars_parse_global_set_var },
	{ CFG_GLOBAL, "set-var-fmt",          vars_parse_global_set_var },
	{ CFG_GLOBAL, "tune.vars.global-max-size", vars_max_size_global },
	{ CFG_GLOBAL, "tune.vars.proc-max-size",   vars_max_size_proc   },
	{ CFG_GLOBAL, "tune.vars.sess-max-size",   vars_max_size_sess   },
	{ CFG_GLOBAL, "tune.vars.txn-max-size",    vars_max_size_txn    },
	{ CFG_GLOBAL, "tune.vars.reqres-max-size", vars_max_size_reqres },
	{ CFG_GLOBAL, "tune.vars.check-max-size",  vars_max_size_check  },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);


/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "get",   "var", NULL }, "get var <name>                          : retrieve contents of a process-wide variable", vars_parse_cli_get_var, NULL },
	{ { "set",   "var", NULL }, "set var <name> [fmt|expr] {<fmt>|<expr>}: set variable from an expression or a format",  vars_parse_cli_set_var, NULL, NULL, NULL, ACCESS_EXPERIMENTAL },
	{ { NULL }, NULL, NULL, NULL }
}};
INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
