#include <ctype.h>

#include <common/cfgparse.h>
#include <common/http.h>
#include <common/initcall.h>
#include <common/mini-clist.h>

#include <types/vars.h>

#include <proto/arg.h>
#include <proto/http_rules.h>
#include <proto/http_ana.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/tcp_rules.h>
#include <proto/vars.h>

/* This contains a pool of struct vars */
DECLARE_STATIC_POOL(var_pool, "vars", sizeof(struct var));

/* This array contain all the names of all the HAProxy vars.
 * This permits to identify two variables name with
 * only one pointer. It permits to not using  strdup() for
 * each variable name used during the runtime.
 */
static char **var_names = NULL;
static int var_names_nb = 0;

/* This array of int contains the system limits per context. */
static unsigned int var_global_limit = 0;
static unsigned int var_global_size = 0;
static unsigned int var_proc_limit = 0;
static unsigned int var_sess_limit = 0;
static unsigned int var_txn_limit = 0;
static unsigned int var_reqres_limit = 0;

__decl_rwlock(var_names_rwlock);

/* returns the struct vars pointer for a session, stream and scope, or NULL if
 * it does not exist.
 */
static inline struct vars *get_vars(struct session *sess, struct stream *strm, enum vars_scope scope)
{
	switch (scope) {
	case SCOPE_PROC:
		return &global.vars;
	case SCOPE_SESS:
		return &sess->vars;
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
static void var_accounting_diff(struct vars *vars, struct session *sess, struct stream *strm, int size)
{
	switch (vars->scope) {
	case SCOPE_REQ:
	case SCOPE_RES:
		if (strm)
			_HA_ATOMIC_ADD(&strm->vars_reqres.size, size);
		/* fall through */
	case SCOPE_TXN:
		if (strm)
			_HA_ATOMIC_ADD(&strm->vars_txn.size, size);
		/* fall through */
	case SCOPE_SESS:
		_HA_ATOMIC_ADD(&sess->vars.size, size);
		/* fall through */
	case SCOPE_PROC:
		_HA_ATOMIC_ADD(&global.vars.size, size);
		_HA_ATOMIC_ADD(&var_global_size, size);
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
		/* fall through */
	case SCOPE_SESS:
		if (var_sess_limit && sess->vars.size + size > var_sess_limit)
			return 0;
		/* fall through */
	case SCOPE_PROC:
		if (var_proc_limit && global.vars.size + size > var_proc_limit)
			return 0;
		if (var_global_limit && var_global_size + size > var_global_limit)
			return 0;
	}
	var_accounting_diff(vars, sess, strm, size);
	return 1;
}

/* This fnuction remove a variable from the list and free memory it used */
unsigned int var_clear(struct var *var)
{
	unsigned int size = 0;

	if (var->data.type == SMP_T_STR || var->data.type == SMP_T_BIN) {
		free(var->data.u.str.area);
		size += var->data.u.str.data;
	}
	else if (var->data.type == SMP_T_METH && var->data.u.meth.meth == HTTP_METH_OTHER) {
		free(var->data.u.meth.str.area);
		size += var->data.u.meth.str.data;
	}
	LIST_DEL(&var->l);
	pool_free(var_pool, var);
	size += sizeof(struct var);
	return size;
}

/* This function free all the memory used by all the variables
 * in the list.
 */
void vars_prune(struct vars *vars, struct session *sess, struct stream *strm)
{
	struct var *var, *tmp;
	unsigned int size = 0;

	HA_RWLOCK_WRLOCK(VARS_LOCK, &vars->rwlock);
	list_for_each_entry_safe(var, tmp, &vars->head, l) {
		size += var_clear(var);
	}
	HA_RWLOCK_WRUNLOCK(VARS_LOCK, &vars->rwlock);
	var_accounting_diff(vars, sess, strm, -size);
}

/* This function frees all the memory used by all the session variables in the
 * list starting at <vars>.
 */
void vars_prune_per_sess(struct vars *vars)
{
	struct var *var, *tmp;
	unsigned int size = 0;

	HA_RWLOCK_WRLOCK(VARS_LOCK, &vars->rwlock);
	list_for_each_entry_safe(var, tmp, &vars->head, l) {
		size += var_clear(var);
	}
	HA_RWLOCK_WRUNLOCK(VARS_LOCK, &vars->rwlock);

	_HA_ATOMIC_SUB(&vars->size, size);
	_HA_ATOMIC_SUB(&global.vars.size, size);
	_HA_ATOMIC_SUB(&var_global_size, size);
}

/* This function init a list of variabes. */
void vars_init(struct vars *vars, enum vars_scope scope)
{
	LIST_INIT(&vars->head);
	vars->scope = scope;
	vars->size = 0;
	HA_RWLOCK_INIT(&vars->rwlock);
}

/* This function declares a new variable name. It returns a pointer
 * on the string identifying the name. This function assures that
 * the same name exists only once.
 *
 * This function check if the variable name is acceptable.
 *
 * The function returns NULL if an error occurs, and <err> is filled.
 * In this case, the HAProxy must be stopped because the structs are
 * left inconsistent. Otherwise, it returns the pointer on the global
 * name.
 */
static char *register_name(const char *name, int len, enum vars_scope *scope,
			   int alloc, char **err)
{
	int i;
	char **var_names2;
	const char *tmp;
	char *res = NULL;

	/* Check length. */
	if (len == 0) {
		memprintf(err, "Empty variable name cannot be accepted");
		return res;
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
	else {
		memprintf(err, "invalid variable name '%s'. A variable name must be start by its scope. "
		               "The scope can be 'proc', 'sess', 'txn', 'req' or 'res'", name);
		return res;
	}

	if (alloc)
		HA_RWLOCK_WRLOCK(VARS_LOCK, &var_names_rwlock);
	else
		HA_RWLOCK_RDLOCK(VARS_LOCK, &var_names_rwlock);


	/* Look for existing variable name. */
	for (i = 0; i < var_names_nb; i++)
		if (strncmp(var_names[i], name, len) == 0 && var_names[i][len] == '\0') {
			res = var_names[i];
			goto end;
		}

	if (!alloc) {
		res = NULL;
		goto end;
	}

	/* Store variable name. If realloc fails, var_names remains valid */
	var_names2 = realloc(var_names, (var_names_nb + 1) * sizeof(*var_names));
	if (!var_names2) {
		memprintf(err, "out of memory error");
		res = NULL;
		goto end;
	}
	var_names_nb++;
	var_names = var_names2;
	var_names[var_names_nb - 1] = malloc(len + 1);
	if (!var_names[var_names_nb - 1]) {
		memprintf(err, "out of memory error");
		res = NULL;
		goto end;
	}
	memcpy(var_names[var_names_nb - 1], name, len);
	var_names[var_names_nb - 1][len] = '\0';

	/* Check variable name syntax. */
	tmp = var_names[var_names_nb - 1];
	while (*tmp) {
		if (!isalnum((int)(unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
			memprintf(err, "invalid syntax at char '%s'", tmp);
			res = NULL;
			goto end;
		}
		tmp++;
	}
	res = var_names[var_names_nb - 1];

  end:
	if (alloc)
		HA_RWLOCK_WRUNLOCK(VARS_LOCK, &var_names_rwlock);
	else
		HA_RWLOCK_RDUNLOCK(VARS_LOCK, &var_names_rwlock);

	return res;
}

/* This function returns an existing variable or returns NULL. */
static inline struct var *var_get(struct vars *vars, const char *name)
{
	struct var *var;

	list_for_each_entry(var, &vars->head, l)
		if (var->name == name)
			return var;
	return NULL;
}

/* Returns 0 if fails, else returns 1. */
static int smp_fetch_var(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const struct var_desc *var_desc = &args[0].data.var;
	struct var *var;
	struct vars *vars;

	/* Check the availibity of the variable. */
	vars = get_vars(smp->sess, smp->strm, var_desc->scope);
	if (!vars || vars->scope != var_desc->scope)
		return 0;

	HA_RWLOCK_RDLOCK(VARS_LOCK, &vars->rwlock);
	var = var_get(vars, var_desc->name);

	/* check for the variable avalaibility */
	if (!var) {
		HA_RWLOCK_RDUNLOCK(VARS_LOCK, &vars->rwlock);
		return 0;
	}

	/* Duplicate the sample data because it could modified by another
	 * thread */
	smp->data = var->data;
	smp_dup(smp);
	smp->flags |= SMP_F_CONST;

	HA_RWLOCK_RDUNLOCK(VARS_LOCK, &vars->rwlock);
	return 1;
}

/* This function search in the <head> a variable with the same
 * pointer value that the <name>. If the variable doesn't exists,
 * create it. The function stores a copy of smp> if the variable.
 * It returns 0 if fails, else returns 1.
 */
static int sample_store(struct vars *vars, const char *name, struct sample *smp)
{
	struct var *var;

	/* Look for existing variable name. */
	var = var_get(vars, name);

	if (var) {
		/* free its used memory. */
		if (var->data.type == SMP_T_STR ||
		    var->data.type == SMP_T_BIN) {
			free(var->data.u.str.area);
			var_accounting_diff(vars, smp->sess, smp->strm,
					    -var->data.u.str.data);
		}
		else if (var->data.type == SMP_T_METH && var->data.u.meth.meth == HTTP_METH_OTHER) {
			free(var->data.u.meth.str.area);
			var_accounting_diff(vars, smp->sess, smp->strm,
					    -var->data.u.meth.str.data);
		}
	} else {

		/* Check memory available. */
		if (!var_accounting_add(vars, smp->sess, smp->strm, sizeof(struct var)))
			return 0;

		/* Create new entry. */
		var = pool_alloc(var_pool);
		if (!var)
			return 0;
		LIST_ADDQ(&vars->head, &var->l);
		var->name = name;
	}

	/* Set type. */
	var->data.type = smp->data.type;

	/* Copy data. If the data needs memory, the function can fail. */
	switch (var->data.type) {
	case SMP_T_BOOL:
	case SMP_T_SINT:
		var->data.u.sint = smp->data.u.sint;
		break;
	case SMP_T_IPV4:
		var->data.u.ipv4 = smp->data.u.ipv4;
		break;
	case SMP_T_IPV6:
		var->data.u.ipv6 = smp->data.u.ipv6;
		break;
	case SMP_T_STR:
	case SMP_T_BIN:
		if (!var_accounting_add(vars, smp->sess, smp->strm, smp->data.u.str.data)) {
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.str.area = malloc(smp->data.u.str.data);
		if (!var->data.u.str.area) {
			var_accounting_diff(vars, smp->sess, smp->strm,
					    -smp->data.u.str.data);
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.str.data = smp->data.u.str.data;
		memcpy(var->data.u.str.area, smp->data.u.str.area,
		       var->data.u.str.data);
		break;
	case SMP_T_METH:
		var->data.u.meth.meth = smp->data.u.meth.meth;
		if (smp->data.u.meth.meth != HTTP_METH_OTHER)
			break;

		if (!var_accounting_add(vars, smp->sess, smp->strm, smp->data.u.meth.str.data)) {
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.meth.str.area = malloc(smp->data.u.meth.str.data);
		if (!var->data.u.meth.str.area) {
			var_accounting_diff(vars, smp->sess, smp->strm,
					    -smp->data.u.meth.str.data);
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.meth.str.data = smp->data.u.meth.str.data;
		var->data.u.meth.str.size = smp->data.u.meth.str.data;
		memcpy(var->data.u.meth.str.area, smp->data.u.meth.str.area,
		       var->data.u.meth.str.data);
		break;
	}
	return 1;
}

/* Returns 0 if fails, else returns 1. Note that stream may be null for SCOPE_SESS. */
static inline int sample_store_stream(const char *name, enum vars_scope scope, struct sample *smp)
{
	struct vars *vars;
	int ret;

	vars = get_vars(smp->sess, smp->strm, scope);
	if (!vars || vars->scope != scope)
		return 0;

	HA_RWLOCK_WRLOCK(VARS_LOCK, &vars->rwlock);
	ret = sample_store(vars, name, smp);
	HA_RWLOCK_WRUNLOCK(VARS_LOCK, &vars->rwlock);
	return ret;
}

/* Returns 0 if fails, else returns 1. Note that stream may be null for SCOPE_SESS. */
static inline int sample_clear_stream(const char *name, enum vars_scope scope, struct sample *smp)
{
	struct vars *vars;
	struct var  *var;
	unsigned int size = 0;

	vars = get_vars(smp->sess, smp->strm, scope);
	if (!vars || vars->scope != scope)
		return 0;

	/* Look for existing variable name. */
	HA_RWLOCK_WRLOCK(VARS_LOCK, &vars->rwlock);
	var = var_get(vars, name);
	if (var) {
		size = var_clear(var);
		var_accounting_diff(vars, smp->sess, smp->strm, -size);
	}
	HA_RWLOCK_WRUNLOCK(VARS_LOCK, &vars->rwlock);
	return 1;
}

/* Returns 0 if fails, else returns 1. */
static int smp_conv_store(const struct arg *args, struct sample *smp, void *private)
{
	return sample_store_stream(args[0].data.var.name, args[0].data.var.scope, smp);
}

/* Returns 0 if fails, else returns 1. */
static int smp_conv_clear(const struct arg *args, struct sample *smp, void *private)
{
	return sample_clear_stream(args[0].data.var.name, args[0].data.var.scope, smp);
}

/* This functions check an argument entry and fill it with a variable
 * type. The argumen must be a string. If the variable lookup fails,
 * the function returns 0 and fill <err>, otherwise it returns 1.
 */
int vars_check_arg(struct arg *arg, char **err)
{
	char *name;
	enum vars_scope scope;

	/* Check arg type. */
	if (arg->type != ARGT_STR) {
		memprintf(err, "unexpected argument type");
		return 0;
	}

	/* Register new variable name. */
	name = register_name(arg->data.str.area, arg->data.str.data, &scope,
			     1,
			     err);
	if (!name)
		return 0;

	/* properly destroy the chunk */
	chunk_destroy(&arg->data.str);

	/* Use the global variable name pointer. */
	arg->type = ARGT_VAR;
	arg->data.var.name = name;
	arg->data.var.scope = scope;
	return 1;
}

/* This function store a sample in a variable if it was already defined.
 * In error case, it fails silently.
 */
void vars_set_by_name_ifexist(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, 0, NULL);
	if (!name)
		return;

	sample_store_stream(name, scope, smp);
}


/* This function store a sample in a variable.
 * In error case, it fails silently.
 */
void vars_set_by_name(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, 1, NULL);
	if (!name)
		return;

	sample_store_stream(name, scope, smp);
}

/* This function unset a variable if it was already defined.
 * In error case, it fails silently.
 */
void vars_unset_by_name_ifexist(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, 0, NULL);
	if (!name)
		return;

	sample_clear_stream(name, scope, smp);
}


/* This function unset a variable.
 * In error case, it fails silently.
 */
void vars_unset_by_name(const char *name, size_t len, struct sample *smp)
{
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, 1, NULL);
	if (!name)
		return;

	sample_clear_stream(name, scope, smp);
}

/* this function fills a sample with the
 * variable content. Returns 1 if the sample
 * is filled, otherwise it returns 0.
 */
int vars_get_by_name(const char *name, size_t len, struct sample *smp)
{
	struct vars *vars;
	struct var *var;
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, 1, NULL);
	if (!name)
		return 0;

	/* Select "vars" pool according with the scope. */
	vars = get_vars(smp->sess, smp->strm, scope);
	if (!vars || vars->scope != scope)
		return 0;

	/* Get the variable entry. */
	var = var_get(vars, name);
	if (!var)
		return 0;

	/* Copy sample. */
	smp->data = var->data;
	smp->flags = SMP_F_CONST;
	return 1;
}

/* this function fills a sample with the
 * content of the variable described by <var_desc>. Returns 1
 * if the sample is filled, otherwise it returns 0.
 */
int vars_get_by_desc(const struct var_desc *var_desc, struct sample *smp)
{
	struct vars *vars;
	struct var *var;

	/* Select "vars" pool according with the scope. */
	vars = get_vars(smp->sess, smp->strm, var_desc->scope);

	/* Check if the scope is available a this point of processing. */
	if (!vars || vars->scope != var_desc->scope)
		return 0;

	/* Get the variable entry. */
	var = var_get(vars, var_desc->name);
	if (!var)
		return 0;

	/* Copy sample. */
	smp->data = var->data;
	smp->flags = SMP_F_CONST;
	return 1;
}

/* Always returns ACT_RET_CONT even if an error occurs. */
static enum act_return action_store(struct act_rule *rule, struct proxy *px,
                                    struct session *sess, struct stream *s, int flags)
{
	struct sample smp;
	int dir;

	switch (rule->from) {
	case ACT_F_TCP_REQ_SES: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_REQ_CNT: dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_TCP_RES_CNT: dir = SMP_OPT_DIR_RES; break;
	case ACT_F_HTTP_REQ:    dir = SMP_OPT_DIR_REQ; break;
	case ACT_F_HTTP_RES:    dir = SMP_OPT_DIR_RES; break;
	default:
		send_log(px, LOG_ERR, "Vars: internal error while execute action store.");
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			ha_alert("Vars: internal error while execute action store.\n");
		return ACT_RET_CONT;
	}

	/* Process the expression. */
	memset(&smp, 0, sizeof(smp));
	if (!sample_process(px, sess, s, dir|SMP_OPT_FINAL,
	                    rule->arg.vars.expr, &smp))
		return ACT_RET_CONT;

	/* Store the sample, and ignore errors. */
	sample_store_stream(rule->arg.vars.name, rule->arg.vars.scope, &smp);
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
	sample_clear_stream(rule->arg.vars.name, rule->arg.vars.scope, &smp);
	return ACT_RET_CONT;
}

/* This two function checks the variable name and replace the
 * configuration string name by the global string name. its
 * the same string, but the global pointer can be easy to
 * compare.
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
	return vars_check_arg(&args[0], err_msg);
}

/* This function is a common parser for using variables. It understands
 * the format:
 *
 *   set-var(<variable-name>) <expression>
 *   unset-var(<variable-name>)
 *
 * It returns ACT_RET_PRS_ERR if fails and <err> is filled with an error
 * message. Otherwise, it returns ACT_RET_PRS_OK and the variable <expr>
 * is filled with the pointer to the expression to execute.
 */
static enum act_parse_ret parse_store(const char **args, int *arg, struct proxy *px,
                                      struct act_rule *rule, char **err)
{
	const char *var_name = args[*arg-1];
	int var_len;
	const char *kw_name;
	int flags, set_var = 0;

	if (!strncmp(var_name, "set-var", 7)) {
		var_name += 7;
		set_var   = 1;
	}
	if (!strncmp(var_name, "unset-var", 9)) {
		var_name += 9;
		set_var   = 0;
	}

	if (*var_name != '(') {
		memprintf(err, "invalid variable '%s'. Expects 'set-var(<var-name>)' or 'unset-var(<var-name>)'",
			  args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}
	var_name++; /* jump the '(' */
	var_len = strlen(var_name);
	var_len--; /* remove the ')' */
	if (var_name[var_len] != ')') {
		memprintf(err, "invalid variable '%s'. Expects 'set-var(<var-name>)' or 'unset-var(<var-name>)'",
			  args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}

	rule->arg.vars.name = register_name(var_name, var_len, &rule->arg.vars.scope, 1, err);
	if (!rule->arg.vars.name)
		return ACT_RET_PRS_ERR;

	/* There is no fetch method when variable is unset. Just set the right
	 * action and return. */
	if (!set_var) {
		rule->action     = ACT_CUSTOM;
		rule->action_ptr = action_clear;
		return ACT_RET_PRS_OK;
	}

	kw_name = args[*arg-1];

	rule->arg.vars.expr = sample_parse_expr((char **)args, arg, px->conf.args.file,
	                                        px->conf.args.line, err, &px->conf.args);
	if (!rule->arg.vars.expr)
		return ACT_RET_PRS_ERR;

	switch (rule->from) {
	case ACT_F_TCP_REQ_SES: flags = SMP_VAL_FE_SES_ACC; break;
	case ACT_F_TCP_REQ_CNT: flags = SMP_VAL_FE_REQ_CNT; break;
	case ACT_F_TCP_RES_CNT: flags = SMP_VAL_BE_RES_CNT; break;
	case ACT_F_HTTP_REQ:    flags = SMP_VAL_FE_HRQ_HDR; break;
	case ACT_F_HTTP_RES:    flags = SMP_VAL_BE_HRS_HDR; break;
	default:
		memprintf(err,
			  "internal error, unexpected rule->from=%d, please report this bug!",
			  rule->from);
		return ACT_RET_PRS_ERR;
	}
	if (!(rule->arg.vars.expr->fetch->val & flags)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  kw_name, sample_src_names(rule->arg.vars.expr->fetch->use));
		free(rule->arg.vars.expr);
		return ACT_RET_PRS_ERR;
	}

	rule->action     = ACT_CUSTOM;
	rule->action_ptr = action_store;
	return ACT_RET_PRS_OK;
}

static int vars_max_size(char **args, int section_type, struct proxy *curpx,
                         struct proxy *defpx, const char *file, int line,
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
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_global_limit);
}

static int vars_max_size_proc(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_proc_limit);
}

static int vars_max_size_sess(char **args, int section_type, struct proxy *curpx,
                              struct proxy *defpx, const char *file, int line,
                              char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_sess_limit);
}

static int vars_max_size_txn(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_txn_limit);
}

static int vars_max_size_reqres(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return vars_max_size(args, section_type, curpx, defpx, file, line, err, &var_reqres_limit);
}

static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {

	{ "var", smp_fetch_var, ARG1(1,STR), smp_check_var, SMP_T_STR, SMP_USE_L4CLI },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);

static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "set-var",   smp_conv_store, ARG1(1,STR), conv_check_var, SMP_T_ANY, SMP_T_ANY },
	{ "unset-var", smp_conv_clear, ARG1(1,STR), conv_check_var, SMP_T_ANY, SMP_T_ANY },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);

static struct action_kw_list tcp_req_sess_kws = { { }, {
	{ "set-var",   parse_store, 1 },
	{ "unset-var", parse_store, 1 },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_sess_keywords_register, &tcp_req_sess_kws);

static struct action_kw_list tcp_req_cont_kws = { { }, {
	{ "set-var",   parse_store, 1 },
	{ "unset-var", parse_store, 1 },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_cont_kws);

static struct action_kw_list tcp_res_kws = { { }, {
	{ "set-var",   parse_store, 1 },
	{ "unset-var", parse_store, 1 },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_kws);

static struct action_kw_list http_req_kws = { { }, {
	{ "set-var",   parse_store, 1 },
	{ "unset-var", parse_store, 1 },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_kws);

static struct action_kw_list http_res_kws = { { }, {
	{ "set-var",   parse_store, 1 },
	{ "unset-var", parse_store, 1 },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_kws);

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "tune.vars.global-max-size", vars_max_size_global },
	{ CFG_GLOBAL, "tune.vars.proc-max-size",   vars_max_size_proc   },
	{ CFG_GLOBAL, "tune.vars.sess-max-size",   vars_max_size_sess   },
	{ CFG_GLOBAL, "tune.vars.txn-max-size",    vars_max_size_txn    },
	{ CFG_GLOBAL, "tune.vars.reqres-max-size", vars_max_size_reqres },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
