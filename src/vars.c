#include <ctype.h>

#include <common/cfgparse.h>
#include <common/mini-clist.h>

#include <types/vars.h>

#include <proto/arg.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/vars.h>

/* This contains a pool of struct vars */
static struct pool_head *var_pool = NULL;

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
static unsigned int var_sess_limit = 0;
static unsigned int var_txn_limit = 0;
static unsigned int var_reqres_limit = 0;

/* This function adds or remove memory size from the accounting. The inner
 * pointers may be null when setting the outer ones only.
 */
static void var_accounting_diff(struct vars *vars, struct vars *per_sess, struct vars *per_strm, struct vars *per_chn, int size)
{
	switch (vars->scope) {
	case SCOPE_REQ:
	case SCOPE_RES:
		per_chn->size += size;
	case SCOPE_TXN:
		per_strm->size += size;
	case SCOPE_SESS:
		per_sess->size += size;
		var_global_size += size;
	}
}

/* This function returns 1 if the <size> is available in the var
 * pool <vars>, otherwise returns 0. If the space is avalaible,
 * the size is reserved. The inner pointers may be null when setting
 * the outer ones only.
 */
static int var_accounting_add(struct vars *vars, struct vars *per_sess, struct vars *per_strm, struct vars *per_chn, int size)
{
	switch (vars->scope) {
	case SCOPE_REQ:
	case SCOPE_RES:
		if (var_reqres_limit && per_chn->size + size > var_reqres_limit)
			return 0;
	case SCOPE_TXN:
		if (var_txn_limit && per_strm->size + size > var_txn_limit)
			return 0;
	case SCOPE_SESS:
		if (var_sess_limit && per_sess->size + size > var_sess_limit)
			return 0;
		if (var_global_limit && var_global_size + size > var_global_limit)
			return 0;
	}
	var_accounting_diff(vars, per_sess, per_strm, per_chn, size);
	return 1;
}

/* This function free all the memory used by all the varaibles
 * in the list.
 */
void vars_prune(struct vars *vars, struct stream *strm)
{
	struct var *var, *tmp;
	unsigned int size = 0;

	list_for_each_entry_safe(var, tmp, &vars->head, l) {
		if (var->data.type == SMP_T_STR ||
		    var->data.type == SMP_T_BIN) {
			free(var->data.u.str.str);
			size += var->data.u.str.len;
		}
		else if (var->data.type == SMP_T_METH) {
			free(var->data.u.meth.str.str);
			size += var->data.u.meth.str.len;
		}
		LIST_DEL(&var->l);
		pool_free2(var_pool, var);
		size += sizeof(struct var);
	}
	var_accounting_diff(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, -size);
}

/* This function frees all the memory used by all the session variables in the
 * list starting at <vars>.
 */
void vars_prune_per_sess(struct vars *vars)
{
	struct var *var, *tmp;
	unsigned int size = 0;

	list_for_each_entry_safe(var, tmp, &vars->head, l) {
		if (var->data.type == SMP_T_STR ||
		    var->data.type == SMP_T_BIN) {
			free(var->data.u.str.str);
			size += var->data.u.str.len;
		}
		else if (var->data.type == SMP_T_METH) {
			free(var->data.u.meth.str.str);
			size += var->data.u.meth.str.len;
		}
		LIST_DEL(&var->l);
		pool_free2(var_pool, var);
		size += sizeof(struct var);
	}
	vars->size      -= size;
	var_global_size -= size;
}

/* This function init a list of variabes. */
void vars_init(struct vars *vars, enum vars_scope scope)
{
	LIST_INIT(&vars->head);
	vars->scope = scope;
	vars->size = 0;
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
static char *register_name(const char *name, int len, enum vars_scope *scope, char **err)
{
	int i;
	const char *tmp;

	/* Check length. */
	if (len == 0) {
		memprintf(err, "Empty variable name cannot be accepted");
		return NULL;
	}

	/* Check scope. */
	if (len > 5 && strncmp(name, "sess.", 5) == 0) {
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
		               "The scope can be 'sess', 'txn', 'req' or 'res'", name);
		return NULL;
	}

	/* Look for existing variable name. */
	for (i = 0; i < var_names_nb; i++)
		if (strncmp(var_names[i], name, len) == 0)
			return var_names[i];

	/* Store variable name. */
	var_names_nb++;
	var_names = realloc(var_names, var_names_nb * sizeof(*var_names));
	if (!var_names) {
		memprintf(err, "out of memory error");
		return NULL;
	}
	var_names[var_names_nb - 1] = malloc(len + 1);
	if (!var_names[var_names_nb - 1]) {
		memprintf(err, "out of memory error");
		return NULL;
	}
	memcpy(var_names[var_names_nb - 1], name, len);
	var_names[var_names_nb - 1][len] = '\0';

	/* Check variable name syntax. */
	tmp = var_names[var_names_nb - 1];
	while (*tmp) {
		if (!isalnum((int)(unsigned char)*tmp) && *tmp != '_') {
			memprintf(err, "invalid syntax at char '%s'", tmp);
			return NULL;
		}
		tmp++;
	}

	/* Return the result. */
	return var_names[var_names_nb - 1];
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
	switch (var_desc->scope) {
	case SCOPE_SESS: vars = &smp->strm->sess->vars;  break;
	case SCOPE_TXN:  vars = &smp->strm->vars_txn;    break;
	case SCOPE_REQ:
	case SCOPE_RES:
	default:         vars = &smp->strm->vars_reqres; break;
	}
	if (vars->scope != var_desc->scope)
		return 0;
	var = var_get(vars, var_desc->name);

	/* check for the variable avalaibility */
	if (!var)
		return 0;

	/* Copy sample. */
	smp->data = var->data;
	smp->flags |= SMP_F_CONST;
	return 1;
}

/* This function search in the <head> a variable with the same
 * pointer value that the <name>. If the variable doesn't exists,
 * create it. The function stores a copy of smp> if the variable.
 * It returns 0 if fails, else returns 1.
 */
static int sample_store(struct vars *vars, const char *name, struct stream *strm, struct sample *smp)
{
	struct var *var;

	/* Look for existing variable name. */
	var = var_get(vars, name);

	if (var) {
		/* free its used memory. */
		if (var->data.type == SMP_T_STR ||
		    var->data.type == SMP_T_BIN) {
			free(var->data.u.str.str);
			var_accounting_diff(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, -var->data.u.str.len);
		}
		else if (var->data.type == SMP_T_METH) {
			free(var->data.u.meth.str.str);
			var_accounting_diff(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, -var->data.u.meth.str.len);
		}
	} else {

		/* Check memory avalaible. */
		if (!var_accounting_add(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, sizeof(struct var)))
			return 0;

		/* Create new entry. */
		var = pool_alloc2(var_pool);
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
		if (!var_accounting_add(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, smp->data.u.str.len)) {
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.str.str = malloc(smp->data.u.str.len);
		if (!var->data.u.str.str) {
			var_accounting_diff(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, -smp->data.u.str.len);
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.str.len = smp->data.u.str.len;
		memcpy(var->data.u.str.str, smp->data.u.str.str, var->data.u.str.len);
		break;
	case SMP_T_METH:
		if (!var_accounting_add(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, smp->data.u.meth.str.len)) {
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.meth.str.str = malloc(smp->data.u.meth.str.len);
		if (!var->data.u.meth.str.str) {
			var_accounting_diff(vars, &strm->sess->vars, &strm->vars_txn, &strm->vars_reqres, -smp->data.u.meth.str.len);
			var->data.type = SMP_T_BOOL; /* This type doesn't use additional memory. */
			return 0;
		}
		var->data.u.meth.meth = smp->data.u.meth.meth;
		var->data.u.meth.str.len = smp->data.u.meth.str.len;
		var->data.u.meth.str.size = smp->data.u.meth.str.len;
		memcpy(var->data.u.meth.str.str, smp->data.u.meth.str.str, var->data.u.meth.str.len);
		break;
	}
	return 1;
}

/* Returns 0 if fails, else returns 1. */
static inline int sample_store_stream(const char *name, enum vars_scope scope,
                                      struct stream *strm, struct sample *smp)
{
	struct vars *vars;

	switch (scope) {
	case SCOPE_SESS: vars = &strm->sess->vars;  break;
	case SCOPE_TXN:  vars = &strm->vars_txn;    break;
	case SCOPE_REQ:
	case SCOPE_RES:
	default:         vars = &strm->vars_reqres; break;
	}
	if (vars->scope != scope)
		return 0;
	return sample_store(vars, name, strm, smp);
}

/* Returns 0 if fails, else returns 1. */
static int smp_conv_store(const struct arg *args, struct sample *smp, void *private)
{
	return sample_store_stream(args[0].data.var.name, args[1].data.var.scope, smp->strm, smp);
}

/* This fucntions check an argument entry and fill it with a variable
 * type. The argumen must be a string. If the variable lookup fails,
 * the function retuns 0 and fill <err>, otherwise it returns 1.
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
	name = register_name(arg->data.str.str, arg->data.str.len, &scope, err);
	if (!name)
		return 0;

	/* Use the global variable name pointer. */
	arg->type = ARGT_VAR;
	arg->data.var.name = name;
	arg->data.var.scope = scope;
	return 1;
}

/* This function store a sample in a variable.
 * In error case, it fails silently.
 */
void vars_set_by_name(const char *name, size_t len, struct stream *strm, struct sample *smp)
{
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, NULL);
	if (!name)
		return;

	sample_store_stream(name, scope, strm, smp);
}

/* this function fills a sample with the
 * variable content. Returns 1 if the sample
 * is filled, otherwise it returns 0.
 */
int vars_get_by_name(const char *name, size_t len, struct stream *strm, struct sample *smp)
{
	struct vars *vars;
	struct var *var;
	enum vars_scope scope;

	/* Resolve name and scope. */
	name = register_name(name, len, &scope, NULL);
	if (!name)
		return 0;

	/* Select "vars" pool according with the scope. */
	switch (scope) {
	case SCOPE_SESS: vars = &strm->sess->vars;  break;
	case SCOPE_TXN:  vars = &strm->vars_txn;    break;
	case SCOPE_REQ:
	case SCOPE_RES:
	default:         vars = &strm->vars_reqres; break;
	}

	/* Check if the scope is avalaible a this point of processing. */
	if (vars->scope != scope)
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
 * content of the varaible described by <var_desc>. Returns 1
 * if the sample is filled, otherwise it returns 0.
 */
int vars_get_by_desc(const struct var_desc *var_desc, struct stream *strm, struct sample *smp)
{
	struct vars *vars;
	struct var *var;

	/* Select "vars" pool according with the scope. */
	switch (var_desc->scope) {
	case SCOPE_SESS: vars = &strm->sess->vars;  break;
	case SCOPE_TXN:  vars = &strm->vars_txn;    break;
	case SCOPE_REQ:
	case SCOPE_RES:
	default:         vars = &strm->vars_reqres; break;
	}

	/* Check if the scope is avalaible a this point of processing. */
	if (vars->scope != var_desc->scope)
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

/* Returns 0 if we need to come back later to complete the sample's retrieval,
 * otherwise 1. For now all processing is considered final so we only return 1.
 */
static inline int action_store(struct sample_expr *expr, const char *name,
                               enum vars_scope scope, struct proxy *px,
                               struct stream *s, int sens)
{
	struct sample smp;

	/* Process the expression. */
	memset(&smp, 0, sizeof(smp));
	if (!sample_process(px, s->sess, s, sens|SMP_OPT_FINAL, expr, &smp))
		return 1;

	/* Store the sample, and ignore errors. */
	sample_store_stream(name, scope, s, &smp);
	return 1;
}

/* Wrapper for action_store */
static int action_tcp_req_store(struct act_rule *rule, struct proxy *px,
                                struct session *sess, struct stream *s)
{
	return action_store(rule->arg.vars.expr, rule->arg.vars.name,
	                    rule->arg.vars.scope, px, s, SMP_OPT_DIR_REQ);
}

/* Wrapper for action_store */
static int action_tcp_res_store(struct act_rule *rule, struct proxy *px,
                                struct session *sess, struct stream *s)
{
	return action_store(rule->arg.vars.expr, rule->arg.vars.name,
	                    rule->arg.vars.scope, px, s, SMP_OPT_DIR_RES);
}

/* Wrapper for action_store */
static int action_http_req_store(struct act_rule *rule, struct proxy *px,
                                 struct session *sess, struct stream *s)
{
	return action_store(rule->arg.vars.expr, rule->arg.vars.name,
	                    rule->arg.vars.scope, px, s, SMP_OPT_DIR_REQ);
}

/* Wrapper for action_store */
static int action_http_res_store(struct act_rule *rule, struct proxy *px,
                                 struct session *sess, struct stream *s)
{
	return action_store(rule->arg.vars.expr, rule->arg.vars.name,
	                    rule->arg.vars.scope, px, s, SMP_OPT_DIR_RES);
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
 *
 * It returns 0 if fails and <err> is filled with an error message. Otherwise,
 * it returns 1 and the variable <expr> is filled with the pointer to the
 * expression to execute.
 */
static int parse_vars(const char **args, int *arg, struct proxy *px,
                      int flags, char **err, struct sample_expr **expr,
                      const char **name, enum vars_scope *scope)
{
	const char *var_name = args[*arg-1];
	int var_len;
	const char *kw_name;

	var_name += strlen("set-var");
	if (*var_name != '(') {
		memprintf(err, "invalid variable '%s'. Expects 'set-var(<var-name>)'", args[*arg-1]);
		return 0;
	}
	var_name++; /* jump the '(' */
	var_len = strlen(var_name);
	var_len--; /* remove the ')' */
	if (var_name[var_len] != ')') {
		memprintf(err, "invalid variable '%s'. Expects 'set-var(<var-name>)'", args[*arg-1]);
		return 0;
	}

	*name = register_name(var_name, var_len, scope, err);
	if (!*name)
		return 0;

	kw_name = args[*arg-1];

	*expr = sample_parse_expr((char **)args, arg, px->conf.args.file, px->conf.args.line,
	                          err, &px->conf.args);
	if (!*expr)
		return 0;

	if (!((*expr)->fetch->val & flags)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  kw_name, sample_src_names((*expr)->fetch->use));
		free(*expr);
		return 0;
	}

	return 1;
}

/* Wrapper for parse_vars */
static int parse_tcp_req_store(const char **args, int *arg, struct proxy *px,
                               struct act_rule *rule, char **err)
{
	if (!parse_vars(args, arg, px, SMP_VAL_FE_REQ_CNT, err,
                   &rule->arg.vars.expr,
                   &rule->arg.vars.name,
                   &rule->arg.vars.scope))
		return 0;
	rule->action       = TCP_ACT_CUSTOM_CONT;
	rule->action_ptr   = action_tcp_req_store;
	return 1;
}

/* Wrapper for parse_vars */
static int parse_tcp_res_store(const char **args, int *arg, struct proxy *px,
                         struct act_rule *rule, char **err)
{
	if (!parse_vars(args, arg, px, SMP_VAL_BE_RES_CNT, err,
                   &rule->arg.vars.expr,
                   &rule->arg.vars.name,
                   &rule->arg.vars.scope))
		return 0;
	rule->action       = TCP_ACT_CUSTOM_CONT;
	rule->action_ptr   = action_tcp_res_store;
	return 1;
}

/* Wrapper for parse_vars */
static int parse_http_req_store(const char **args, int *arg, struct proxy *px,
                         struct act_rule *rule, char **err)
{
	if (!parse_vars(args, arg, px, SMP_VAL_FE_HRQ_HDR, err,
                   &rule->arg.vars.expr,
                   &rule->arg.vars.name,
                   &rule->arg.vars.scope))
		return -1;
	rule->action       = HTTP_REQ_ACT_CUSTOM_CONT;
	rule->action_ptr   = action_http_req_store;
	return 0;
}

/* Wrapper for parse_vars */
static int parse_http_res_store(const char **args, int *arg, struct proxy *px,
                         struct act_rule *rule, char **err)
{
	if (!parse_vars(args, arg, px, SMP_VAL_BE_HRS_HDR, err,
                   &rule->arg.vars.expr,
                   &rule->arg.vars.name,
                   &rule->arg.vars.scope))
		return -1;
	rule->action       = HTTP_RES_ACT_CUSTOM_CONT;
	rule->action_ptr   = action_http_res_store;
	return 0;
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

	{ "var", smp_fetch_var, ARG1(1,STR), smp_check_var, SMP_T_STR, SMP_USE_HTTP_ANY },
	{ /* END */ },
}};

static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "set-var", smp_conv_store, ARG1(1,STR), conv_check_var, SMP_T_ANY, SMP_T_ANY },
	{ /* END */ },
}};

static struct tcp_action_kw_list tcp_req_kws = { { }, {
	{ "set-var", parse_tcp_req_store, 1 },
	{ /* END */ }
}};

static struct tcp_action_kw_list tcp_res_kws = { { }, {
	{ "set-var", parse_tcp_res_store, 1 },
	{ /* END */ }
}};

static struct http_req_action_kw_list http_req_kws = { { }, {
	{ "set-var", parse_http_req_store, 1 },
	{ /* END */ }
}};

static struct http_res_action_kw_list http_res_kws = { { }, {
	{ "set-var", parse_http_res_store, 1 },
	{ /* END */ }
}};

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "tune.vars.global-max-size", vars_max_size_global },
	{ CFG_GLOBAL, "tune.vars.sess-max-size",   vars_max_size_sess   },
	{ CFG_GLOBAL, "tune.vars.txn-max-size",    vars_max_size_txn    },
	{ CFG_GLOBAL, "tune.vars.reqres-max-size", vars_max_size_reqres },
	{ /* END */ }
}};

__attribute__((constructor))
static void __http_protocol_init(void)
{
	var_pool = create_pool("vars", sizeof(struct var), MEM_F_SHARED);

	sample_register_fetches(&sample_fetch_keywords);
	sample_register_convs(&sample_conv_kws);
	tcp_req_cont_keywords_register(&tcp_req_kws);
	tcp_res_cont_keywords_register(&tcp_res_kws);
	http_req_keywords_register(&http_req_kws);
	http_res_keywords_register(&http_res_kws);
	cfg_register_keywords(&cfg_kws);
}
