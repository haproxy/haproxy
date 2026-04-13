/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/*
 * OpenTelemetry filter id, used to identify OpenTelemetry filters.  The name
 * of this variable is consistent with the other filter names declared in
 * include/haproxy/filters.h .
 */
const char *otel_flt_id = "the OpenTelemetry filter";

/* Counter of OTel SDK internal diagnostic messages. */
uint64_t flt_otel_drop_cnt = 0;

#if defined(USE_THREAD) && defined(DEBUG_OTEL)
/* Counter for assigning unique IDs to threads not registered as workers. */
static int flt_otel_thread_id_offset = -1;

/* Per-thread registration data for HAProxy worker threads. */
static struct {
	pthread_t id;         /* POSIX thread ID. */
	bool      registered; /* Entry is valid. */
} flt_otel_tid[MAX_THREADS + 1];
#endif


/***
 * NAME
 *   flt_otel_mem_malloc - OTel library memory allocator callback
 *
 * SYNOPSIS
 *   static void *flt_otel_mem_malloc(const char *func, int line, size_t size)
 *
 * ARGUMENTS
 *   func - caller function name (debug only)
 *   line - caller source line number (debug only)
 *   size - number of bytes to allocate
 *
 * DESCRIPTION
 *   Allocator callback for the OpenTelemetry C wrapper library.  It allocates
 *   the requested <size> bytes from the HAProxy pool_head_otel_span_context
 *   pool.  This function is registered via otelc_ext_init().
 *
 * RETURN VALUE
 *   Returns a pointer to the allocated memory, or NULL on failure.
 */
static void *flt_otel_mem_malloc(FLT_OTEL_DBG_ARGS(const char *func, int line, ) size_t size)
{
	return flt_otel_pool_alloc(pool_head_otel_span_context, size, 1, NULL);
}


/***
 * NAME
 *   flt_otel_mem_free - OTel library memory deallocator callback
 *
 * SYNOPSIS
 *   static void flt_otel_mem_free(const char *func, int line, void *ptr)
 *
 * ARGUMENTS
 *   func - caller function name (debug only)
 *   line - caller source line number (debug only)
 *   ptr  - pointer to the memory to free
 *
 * DESCRIPTION
 *   Deallocator callback for the OpenTelemetry C wrapper library.  It returns
 *   the memory pointed to by <ptr> back to the HAProxy
 *   pool_head_otel_span_context pool.  This function is registered via
 *   otelc_ext_init().
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_mem_free(FLT_OTEL_DBG_ARGS(const char *func, int line, ) void *ptr)
{
	flt_otel_pool_free(pool_head_otel_span_context, &ptr);
}


/***
 * NAME
 *   flt_otel_thread_id - OTel library thread ID callback
 *
 * SYNOPSIS
 *   static int flt_otel_thread_id(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Thread ID callback for the OpenTelemetry C wrapper library.  For registered
 *   HAProxy worker threads it returns the HAProxy thread identifier (tid).  For
 *   unregistered threads, such as those created internally by the OTel SDK, it
 *   assigns and returns a unique ID from the atomic offset counter.  This
 *   function is registered via otelc_ext_init().
 *
 * RETURN VALUE
 *   Returns the HAProxy thread ID for worker threads, a unique offset-based ID
 *   for unregistered threads, or -1 if the thread index is out of range or the
 *   offset counter has not yet been initialized.
 */
static int flt_otel_thread_id(void)
{
#if defined(USE_THREAD) && defined(DEBUG_OTEL)
	static THREAD_LOCAL int retval = -1;

	if (!OTELC_IN_RANGE(tid, 0, OTELC_TABLESIZE(flt_otel_tid)))
		return -1;
	else if (!flt_otel_tid[tid].registered)
		return tid;
	else if (pthread_equal(flt_otel_tid[tid].id, pthread_self()))
		return tid;

	if ((retval == -1) && (HA_ATOMIC_LOAD(&flt_otel_thread_id_offset) != -1))
		retval = HA_ATOMIC_FETCH_ADD(&flt_otel_thread_id_offset, 1);

	return retval;

#else

	return tid;
#endif /* USE_THREAD && DEBUG_OTEL */
}


/***
 * NAME
 *   flt_otel_log_handler_cb - counts SDK internal diagnostic messages
 *
 * SYNOPSIS
 *   static void flt_otel_log_handler_cb(otelc_log_level_t level, const char *file, int line, const char *msg, const struct otelc_kv *attr, size_t attr_len, void *ctx)
 *
 * ARGUMENTS
 *   level    - severity of the OTel SDK diagnostic message
 *   file     - source file that emitted the message
 *   line     - source line number
 *   msg      - formatted diagnostic message text
 *   attr     - array of key-value attributes associated with the message
 *   attr_len - number of entries in the attr array
 *   ctx      - opaque context pointer (unused)
 *
 * DESCRIPTION
 *   Custom OTel SDK internal log handler registered via otelc_log_set_handler().
 *   Each invocation atomically increments the flt_otel_drop_cnt counter so the
 *   HAProxy OTel filter can verify how many OTel SDK diagnostic messages were
 *   emitted.  The message content is intentionally ignored.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_log_handler_cb(otelc_log_level_t level __maybe_unused, const char *file __maybe_unused, int line __maybe_unused, const char *msg __maybe_unused, const struct otelc_kv *attr __maybe_unused, size_t attr_len __maybe_unused, void *ctx __maybe_unused)
{
	OTELC_FUNC("%d, \"%s\", %d, \"%s\", %p, %zu, %p", level, OTELC_STR_ARG(file), line, OTELC_STR_ARG(msg), attr, attr_len, ctx);

	_HA_ATOMIC_INC(&flt_otel_drop_cnt);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_lib_init - OTel library initialization
 *
 * SYNOPSIS
 *   static int flt_otel_lib_init(struct flt_otel_conf_instr *instr, char **err)
 *
 * ARGUMENTS
 *   instr - pointer to the instrumentation configuration
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Initializes the OpenTelemetry C wrapper library for the instrumentation
 *   specified by <instr>.  It verifies the library version, constructs the
 *   absolute configuration path from <instr>->config, calls otelc_init(), and
 *   creates the tracer and meter instances.  On success, it registers the
 *   memory and thread ID callbacks via otelc_ext_init().
 *
 * RETURN VALUE
 *   Returns 0 on success, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_lib_init(struct flt_otel_conf_instr *instr, char **err)
{
	char cwd[PATH_MAX], path[PATH_MAX];
	int  rc, retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, %p:%p", instr, OTELC_DPTR_ARGS(err));

	if (!OTELC_IS_VALID_VERSION()) {
		FLT_OTEL_ERR("OpenTelemetry C Wrapper version mismatch: library (%s) does not match header files (%s).  Please ensure both are the same version.", otelc_version(), OTELC_VERSION);

		OTELC_RETURN_INT(retval);
	}

	if (flt_otel_pool_init() == FLT_OTEL_RET_ERROR) {
		FLT_OTEL_ERR("failed to initialize memory pools");

		OTELC_RETURN_INT(retval);
	}

	flt_otel_pool_info();

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		FLT_OTEL_ERR("failed to get current working directory");

		OTELC_RETURN_INT(retval);
	}

	rc = snprintf(path, sizeof(path), "%s/%s", cwd, instr->config);
	if ((rc == -1) || (rc >= sizeof(path))) {
		FLT_OTEL_ERR("failed to construct the OpenTelemetry configuration path");

		OTELC_RETURN_INT(retval);
	}

	if (otelc_init(path, err) == OTELC_RET_ERROR) {
		if (*err == NULL)
			FLT_OTEL_ERR("%s", "failed to initialize tracing library");

		OTELC_RETURN_INT(retval);
	}

	instr->tracer = otelc_tracer_create(err);
	if (instr->tracer == NULL) {
		if (*err == NULL)
			FLT_OTEL_ERR("%s", "failed to initialize OpenTelemetry tracer");

		OTELC_RETURN_INT(retval);
	}

	instr->meter = otelc_meter_create(err);
	if (instr->meter == NULL) {
		if (*err == NULL)
			FLT_OTEL_ERR("%s", "failed to initialize OpenTelemetry meter");

		OTELC_RETURN_INT(retval);
	}

	instr->logger = otelc_logger_create(err);
	if (instr->logger == NULL) {
		if (*err == NULL)
			FLT_OTEL_ERR("%s", "failed to initialize OpenTelemetry logger");
	} else {
#if defined(USE_THREAD) && defined(DEBUG_OTEL)
		flt_otel_tid[tid].id         = pthread_self();
		flt_otel_tid[tid].registered = true;
		HA_ATOMIC_STORE(&flt_otel_thread_id_offset, 1000);
#endif
		otelc_ext_init(flt_otel_mem_malloc, flt_otel_mem_free, flt_otel_thread_id);
		otelc_log_set_handler(flt_otel_log_handler_cb, NULL, false);

		retval = 0;
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_is_disabled - filter disabled check
 *
 * SYNOPSIS
 *   bool flt_otel_is_disabled(const struct filter *f, int event)
 *
 * ARGUMENTS
 *   f     - the filter instance to check
 *   event - the event identifier, or -1 (debug only)
 *
 * DESCRIPTION
 *   Checks whether the filter instance is disabled for the current stream by
 *   examining the runtime context's flag_disabled field.  When DEBUG_OTEL is
 *   enabled, it also logs the filter name, type and the <event> name.
 *
 * RETURN VALUE
 *   Returns true if the filter is disabled, false otherwise.
 */
bool flt_otel_is_disabled(const struct filter *f FLT_OTEL_DBG_ARGS(, int event))
{
#ifdef DEBUG_OTEL
	const struct flt_otel_conf *conf = FLT_OTEL_CONF(f);
	const char                 *msg;
#endif
	bool                        retval;

	retval = FLT_OTEL_RT_CTX(f->ctx)->flag_disabled ? 1 : 0;

#ifdef DEBUG_OTEL
	msg    = retval ? " (disabled)" : "";

	if (OTELC_IN_RANGE(event, 0, FLT_OTEL_EVENT_MAX - 1))
		OTELC_DBG(NOTICE, "filter '%s', type: %s, event: '%s' %d%s", conf->id, flt_otel_type(f), flt_otel_event_data[event].name, event, msg);
	else
		OTELC_DBG(NOTICE, "filter '%s', type: %s%s", conf->id, flt_otel_type(f), msg);
#endif

	return retval;
}


/***
 * NAME
 *   flt_otel_return_int - error handler for int-returning callbacks
 *
 * SYNOPSIS
 *   static int flt_otel_return_int(const struct filter *f, char **err, int retval)
 *
 * ARGUMENTS
 *   f      - the filter instance
 *   err    - indirect pointer to error message string
 *   retval - the return value from the caller
 *
 * DESCRIPTION
 *   Error handler for filter callbacks that return an integer value.  If
 *   <retval> indicates an error or <err> contains a message, the filter is
 *   disabled when hard-error mode is enabled; in soft-error mode, the error
 *   is silently cleared.  The error message is always freed before returning.
 *
 * RETURN VALUE
 *   Returns FLT_OTEL_RET_OK if an error was handled, or the original <retval>.
 */
static int flt_otel_return_int(const struct filter *f, char **err, int retval)
{
	struct flt_otel_runtime_context *rt_ctx = f->ctx;

	/* Disable the filter on hard errors; ignore on soft errors. */
	if ((retval == FLT_OTEL_RET_ERROR) || ((err != NULL) && (*err != NULL))) {
		if (rt_ctx->flag_harderr) {
			OTELC_DBG(INFO, "WARNING: filter hard-error (disabled)");

			rt_ctx->flag_disabled = 1;

#ifdef FLT_OTEL_USE_COUNTERS
			_HA_ATOMIC_ADD(FLT_OTEL_CONF(f)->cnt.disabled + 1, 1);
#endif
		} else {
			OTELC_DBG(INFO, "WARNING: filter soft-error");
		}

		retval = FLT_OTEL_RET_OK;
	}

	FLT_OTEL_ERR_FREE(*err);

	return retval;
}


/***
 * NAME
 *   flt_otel_return_void - error handler for void-returning callbacks
 *
 * SYNOPSIS
 *   static void flt_otel_return_void(const struct filter *f, char **err)
 *
 * ARGUMENTS
 *   f   - the filter instance
 *   err - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Error handler for filter callbacks that return void.  If <err> contains
 *   a message, the filter is disabled when hard-error mode is enabled; in
 *   soft-error mode, the error is silently cleared.  The error message is
 *   always freed before returning.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_return_void(const struct filter *f, char **err)
{
	struct flt_otel_runtime_context *rt_ctx = f->ctx;

	/* Disable the filter on hard errors; ignore on soft errors. */
	if ((err != NULL) && (*err != NULL)) {
		if (rt_ctx->flag_harderr) {
			OTELC_DBG(INFO, "WARNING: filter hard-error (disabled)");

			rt_ctx->flag_disabled = 1;

#ifdef FLT_OTEL_USE_COUNTERS
			_HA_ATOMIC_ADD(FLT_OTEL_CONF(f)->cnt.disabled + 1, 1);
#endif
		} else {
			OTELC_DBG(INFO, "WARNING: filter soft-error");
		}
	}

	FLT_OTEL_ERR_FREE(*err);
}


/***
 * NAME
 *   flt_otel_ops_init - filter init callback (flt_ops.init)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_init(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   It initializes the filter for a proxy.  You may define this callback if you
 *   need to complete your filter configuration.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_init(struct proxy *p, struct flt_conf *fconf)
{
	struct flt_otel_conf *conf = FLT_OTEL_DEREF(fconf, conf, NULL);
	char                 *err = NULL;
	int                   retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		OTELC_RETURN_INT(retval);

	flt_otel_cli_init();

	/*
	 * Initialize the OpenTelemetry library.
	 */
	retval = flt_otel_lib_init(conf->instr, &err);
	if (retval != FLT_OTEL_RET_ERROR)
		/* Do nothing. */;
	else if (err != NULL) {
		FLT_OTEL_ALERT("%s", err);

		FLT_OTEL_ERR_FREE(err);
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_ops_deinit - filter deinit callback (flt_ops.deinit)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_deinit(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   It cleans up what the parsing function and the init callback have done.
 *   This callback is useful to release memory allocated for the filter
 *   configuration.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_deinit(struct proxy *p, struct flt_conf *fconf)
{
	struct flt_otel_conf **conf = (fconf == NULL) ? NULL : (typeof(conf))&(fconf->conf);
	struct otelc_tracer   *otel_tracer = NULL;
	struct otelc_meter    *otel_meter = NULL;
	struct otelc_logger   *otel_logger = NULL;
#ifdef DEBUG_OTEL
	char                   buffer[BUFSIZ];
	int                    i;
#endif

	OTELC_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		OTELC_RETURN();

#ifdef DEBUG_OTEL
	otelc_statistics(buffer, sizeof(buffer));
	OTELC_DBG(LOG, "%s", buffer);

#  ifdef FLT_OTEL_USE_COUNTERS
	OTELC_DBG(LOG, "attach counters: %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64, (*conf)->cnt.attached[0], (*conf)->cnt.attached[1], (*conf)->cnt.attached[2], (*conf)->cnt.attached[3]);
#  endif

	OTELC_DBG(LOG, "--- used events ----------");
	for (i = 0; i < OTELC_TABLESIZE((*conf)->cnt.event); i++)
		if ((*conf)->cnt.event[i].flag_used)
			OTELC_DBG(LOG, "  %02d %25s: %" PRIu64 " / %" PRIu64, i, flt_otel_event_data[i].an_name, (*conf)->cnt.event[i].htx[0], (*conf)->cnt.event[i].htx[1]);
#endif /* DEBUG_OTEL */

	/*
	 * Save the OTel handles before freeing the configuration.
	 * flt_otel_conf_free() must run while the wrapper's ext callbacks
	 * still point to the HAProxy pool allocator; otelc_deinit() resets
	 * those callbacks, so it runs last.
	 */
	if ((*conf)->instr != NULL) {
		otel_tracer = (*conf)->instr->tracer;
		otel_meter  = (*conf)->instr->meter;
		otel_logger = (*conf)->instr->logger;
	}

	flt_otel_conf_free(conf);
	OTELC_MEMINFO();
	flt_otel_pool_destroy();
	otelc_deinit(&otel_tracer, &otel_meter, &otel_logger);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_check - filter check callback (flt_ops.check)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_check(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   Validates the internal configuration of the OTel filter after the parsing
 *   phase, when the HAProxy configuration is fully defined.  The following
 *   checks are performed: duplicate filter IDs across all proxies, presence of
 *   an instrumentation section and its configuration file, duplicate group and
 *   scope names, empty groups, group-to-scope and instrumentation-to-group/scope
 *   cross-references, unused scopes, root span count, analyzer bits, and
 *   create-form instrument name uniqueness and update-form instrument
 *   resolution.
 *
 * RETURN VALUE
 *   Returns the number of encountered errors.
 */
static int flt_otel_ops_check(struct proxy *p, struct flt_conf *fconf)
{
	struct proxy               *px;
	struct flt_otel_conf       *conf = FLT_OTEL_DEREF(fconf, conf, NULL);
	struct flt_otel_conf_group *conf_group;
	struct flt_otel_conf_scope *conf_scope;
	struct flt_otel_conf_ph    *ph_group, *ph_scope;
	int                         retval = 0, scope_unused_cnt = 0, span_root_cnt = 0;

	OTELC_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		OTELC_RETURN_INT(++retval);

	/*
	 * Resolve deferred OTEL sample fetch arguments.
	 *
	 * These were kept out of the proxy's arg list during parsing to avoid
	 * the global smp_resolve_args() call, which would reject backend-only
	 * fetches on a frontend proxy.  All backends and servers are now
	 * available, so resolve under full FE+BE capabilities.
	 */
	if (!LIST_ISEMPTY(&(conf->smp_args))) {
		char *err = NULL;
		uint  saved_cap = p->cap;

		LIST_SPLICE(&(p->conf.args.list), &(conf->smp_args));
		LIST_INIT(&(conf->smp_args));
		p->cap |= PR_CAP_LISTEN;

		if (smp_resolve_args(p, &err) != 0) {
			FLT_OTEL_ALERT("%s", err);
			ha_free(&err);

			retval++;
		}

		p->cap = saved_cap;
	}

	/*
	 * If only the proxy specified with the <p> parameter is checked, then
	 * no duplicate filters can be found that are not defined in the same
	 * configuration sections.
	 */
	for (px = proxies_list; px != NULL; px = px->next) {
		struct flt_conf *fconf_tmp;

		OTELC_DBG(NOTICE, "proxy '%s'", px->id);

		/*
		 * The names of all OTEL filters (filter ID) should be checked,
		 * they must be unique.
		 */
		list_for_each_entry(fconf_tmp, &(px->filter_configs), list)
			if ((fconf_tmp != fconf) && (fconf_tmp->id == otel_flt_id)) {
				struct flt_otel_conf *conf_tmp = fconf_tmp->conf;

				OTELC_DBG(NOTICE, "  OTEL filter '%s'", conf_tmp->id);

				if (strcmp(conf_tmp->id, conf->id) == 0) {
					FLT_OTEL_ALERT("''%s' : duplicated filter ID'", conf_tmp->id);

					retval++;
				}
			}
	}

	if (FLT_OTEL_DEREF(conf->instr, id, NULL) == NULL) {
		FLT_OTEL_ALERT("''%s' : no instrumentation found'", conf->id);

		retval++;
	}

	if ((conf->instr != NULL) && (conf->instr->config == NULL)) {
		FLT_OTEL_ALERT("''%s' : no configuration file specified'", conf->instr->id);

		retval++;
	}

	/*
	 * Checking that defined 'otel-group' section names are unique.
	 */
	list_for_each_entry(conf_group, &(conf->groups), list) {
		struct flt_otel_conf_group *conf_group_tmp;

		list_for_each_entry(conf_group_tmp, &(conf->groups), list) {
			if ((conf_group_tmp != conf_group) && (strcmp(conf_group_tmp->id, conf_group->id) == 0)) {
				FLT_OTEL_ALERT("''%s' : duplicated " FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s''", conf->id, conf_group->id);

				retval++;

				break;
			}
		}
	}

	/*
	 * Checking that defined 'otel-scope' section names are unique.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		struct flt_otel_conf_scope *conf_scope_tmp;

		list_for_each_entry(conf_scope_tmp, &(conf->scopes), list) {
			if ((conf_scope_tmp != conf_scope) && (strcmp(conf_scope_tmp->id, conf_scope->id) == 0)) {
				FLT_OTEL_ALERT("''%s' : duplicated " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf->id, conf_scope->id);

				retval++;

				break;
			}
		}
	}

	/*
	 * Checking that defined 'otel-group' sections are not empty.
	 */
	list_for_each_entry(conf_group, &(conf->groups), list)
		if (LIST_ISEMPTY(&(conf_group->ph_scopes)))
			FLT_OTEL_ALERT("''%s' : " FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s' has no scopes'", conf->id, conf_group->id);

	/*
	 * Checking that all defined 'otel-group' sections have correctly declared
	 * 'otel-scope' sections (ie whether the declared 'otel-scope' sections have
	 * corresponding definitions).
	 */
	list_for_each_entry(conf_group, &(conf->groups), list)
		list_for_each_entry(ph_scope, &(conf_group->ph_scopes), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_scope, &(conf->scopes), list)
				if (strcmp(ph_scope->id, conf_scope->id) == 0) {
					ph_scope->ptr         = conf_scope;
					conf_scope->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s' : references undefined " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf_group->id, ph_scope->id);

				retval++;
			}
		}

	if (conf->instr != NULL) {
		/*
		 * Checking that all declared 'groups' keywords have correctly
		 * defined 'otel-group' sections.
		 */
		list_for_each_entry(ph_group, &(conf->instr->ph_groups), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_group, &(conf->groups), list)
				if (strcmp(ph_group->id, conf_group->id) == 0) {
					ph_group->ptr         = conf_group;
					conf_group->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_INSTR_ID " '%s' : references undefined " FLT_OTEL_PARSE_SECTION_GROUP_ID " '%s''", conf->instr->id, ph_group->id);

				retval++;
			}
		}

		/*
		 * Checking that all declared 'scopes' keywords have correctly
		 * defined 'otel-scope' sections.
		 */
		list_for_each_entry(ph_scope, &(conf->instr->ph_scopes), list) {
			bool flag_found = 0;

			list_for_each_entry(conf_scope, &(conf->scopes), list)
				if (strcmp(ph_scope->id, conf_scope->id) == 0) {
					ph_scope->ptr         = conf_scope;
					conf_scope->flag_used = 1;
					flag_found            = 1;

					break;
				}

			if (!flag_found) {
				FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_INSTR_ID " '%s' : references undefined " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf->instr->id, ph_scope->id);

				retval++;
			}
		}
	}

	OTELC_DBG(DEBUG, "--- filter '%s' configuration ----------", conf->id);
	OTELC_DBG(DEBUG, "- defined spans ----------");

	/*
	 * Walk every configured scope: for used ones, log the defined spans,
	 * count root spans, and set the required analyzer bits; for unused
	 * ones, record a warning so the operator is notified.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		if (conf_scope->flag_used) {
			struct flt_otel_conf_span *conf_span;

			/*
			 * In principle, only one span should be labeled
			 * as a root span.
			 */
			list_for_each_entry(conf_span, &(conf_scope->spans), list) {
				FLT_OTEL_DBG_CONF_SPAN("   ", conf_span);

				span_root_cnt += conf_span->flag_root ? 1 : 0;
			}

#ifdef DEBUG_OTEL
			conf->cnt.event[conf_scope->event].flag_used = 1;
#endif

			/* Set the flags of the analyzers used. */
			conf->instr->analyzers |= flt_otel_event_data[conf_scope->event].an_bit;

			/* Track the minimum idle timeout. */
			if (conf_scope->event == FLT_OTEL_EVENT__IDLE_TIMEOUT)
				if ((conf->instr->idle_timeout == 0) || (conf_scope->idle_timeout < conf->instr->idle_timeout))
					conf->instr->idle_timeout = conf_scope->idle_timeout;
		} else {
			FLT_OTEL_ALERT("''%s' : unused " FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s''", conf->id, conf_scope->id);

			scope_unused_cnt++;
		}
	}

	/*
	 * Unused scopes or a number of root spans other than one do not
	 * necessarily have to be errors, but it is good to print it when
	 * starting HAProxy.
	 */
	if (scope_unused_cnt > 0)
		FLT_OTEL_ALERT("''%s' : %d scope(s) not in use'", conf->id, scope_unused_cnt);

	if (LIST_ISEMPTY(&(conf->scopes)))
		/* Do nothing. */;
	else if (span_root_cnt == 0)
		FLT_OTEL_ALERT("''%s' : no span is marked as the root span'", conf->id);
	else if (span_root_cnt > 1)
		FLT_OTEL_ALERT("''%s' : multiple spans are marked as the root span'", conf->id);

	OTELC_DBG(DEBUG, "- defined instruments ----------");

	/*
	 * Validate update-form instruments: for each one, resolve its reference
	 * to the matching create-form instrument definition.
	 *
	 * Validate create-form instruments: check that names are unique across
	 * all scopes.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		struct flt_otel_conf_instrument *conf_instr, *instr;
		struct flt_otel_conf_scope      *scope;

		list_for_each_entry(conf_instr, &(conf_scope->instruments), list) {
			if (conf_instr->type == OTELC_METRIC_INSTRUMENT_UPDATE) {
				FLT_OTEL_DBG_CONF_INSTRUMENT("  update ", conf_instr);

				/*
				 * Search all scopes for a create-form instrument
				 * whose name matches this update-form instrument.
				 */
				list_for_each_entry(scope, &(conf->scopes), list) {
					list_for_each_entry(instr, &(scope->instruments), list) {
						if ((instr->type != OTELC_METRIC_INSTRUMENT_UPDATE) && (strcmp(instr->id, conf_instr->id) == 0))
							conf_instr->ref = instr;

						if (conf_instr->ref != NULL)
							break;
					}

					if (conf_instr->ref != NULL)
						break;
				}

				if (conf_instr->ref == NULL) {
					FLT_OTEL_ALERT("''%s' : update-form instrument has no matching create-form definition'", conf_instr->id);

					retval++;
				}
			} else {
				bool flag_past = false, flag_dup = false;

				FLT_OTEL_DBG_CONF_INSTRUMENT("  create ", conf_instr);

				if (LIST_ISEMPTY(&(conf_instr->samples))) {
					FLT_OTEL_ALERT("''%s' : create-form instrument '%s' has no value expression'", conf->id, conf_instr->id);

					retval++;
				}

				if ((conf_instr->aggr_type == OTELC_METRIC_AGGREGATION_UNSET) && (conf_instr->type == OTELC_METRIC_INSTRUMENT_HISTOGRAM_UINT64))
					conf_instr->aggr_type = OTELC_METRIC_AGGREGATION_HISTOGRAM;

				/*
				 * Checking that create-form instrument names
				 * are unique across all scopes.  Only compare
				 * forward to avoid reporting the same pair
				 * twice.
				 */
				list_for_each_entry(scope, &(conf->scopes), list) {
					list_for_each_entry(instr, &(scope->instruments), list)
						if (instr == conf_instr) {
							flag_past = true;

							continue;
						}
						else if (!flag_past || (instr->type == OTELC_METRIC_INSTRUMENT_UPDATE)) {
							continue;
						}
						else if (strcmp(instr->id, conf_instr->id) == 0) {
							FLT_OTEL_ALERT("''%s' : duplicated create-form instrument '%s''", conf->id, conf_instr->id);

							retval++;

							flag_dup = true;
							break;
						}

					if (flag_dup)
						break;
				}
			}
		}
	}

	OTELC_DBG(DEBUG, "- defined log records ----------");

	/*
	 * Validate log-record span references: for each log-record that
	 * names a span, verify that a span with that name exists in one
	 * of the configured scopes.
	 */
	list_for_each_entry(conf_scope, &(conf->scopes), list) {
		struct flt_otel_conf_log_record *conf_log;

		list_for_each_entry(conf_log, &(conf_scope->log_records), list) {
			FLT_OTEL_DBG_CONF_LOG_RECORD("  ", conf_log);

			if (conf_log->span != NULL) {
				struct flt_otel_conf_scope *find_scope;
				struct flt_otel_conf_span  *find_span;
				bool                        flag_found = false;

				list_for_each_entry(find_scope, &(conf->scopes), list) {
					list_for_each_entry(find_span, &(find_scope->spans), list)
						if (strcmp(find_span->id, conf_log->span) == 0) {
							flag_found = true;

							break;
						}

					if (flag_found)
						break;
				}

				if (!flag_found) {
					FLT_OTEL_ALERT("'" FLT_OTEL_PARSE_SECTION_SCOPE_ID " '%s' : log-record references undefined span '%s''", conf_scope->id, conf_log->span);

					retval++;
				}
			}
		}
	}

	FLT_OTEL_DBG_LIST(conf, group, "", "defined", _group,
	                  FLT_OTEL_DBG_CONF_GROUP("   ", _group);
	                  FLT_OTEL_DBG_LIST(_group, ph_scope, "   ", "used", _scope, FLT_OTEL_DBG_CONF_PH("      ", _scope)));
	FLT_OTEL_DBG_LIST(conf, scope, "", "defined", _scope, FLT_OTEL_DBG_CONF_SCOPE("   ", _scope));

	if (conf->instr != NULL) {
		OTELC_DBG(DEBUG, "   --- instrumentation '%s' configuration ----------", conf->instr->id);
		FLT_OTEL_DBG_LIST(conf->instr, ph_group, "   ", "used", _group, FLT_OTEL_DBG_CONF_PH("      ", _group));
		FLT_OTEL_DBG_LIST(conf->instr, ph_scope, "   ", "used", _scope, FLT_OTEL_DBG_CONF_PH("      ", _scope));
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_ops_init_per_thread - per-thread init callback (flt_ops.init_per_thread)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_init_per_thread(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   Per-thread filter initialization called after thread creation.  Starts
 *   the OTel tracer and meter threads via their start operations and enables
 *   HTX stream filtering.  Subsequent calls on the same filter are no-ops.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_init_per_thread(struct proxy *p, struct flt_conf *fconf)
{
	struct flt_otel_conf *conf = FLT_OTEL_DEREF(fconf, conf, NULL);
	int                   retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, %p", p, fconf);

	if (conf == NULL)
		OTELC_RETURN_INT(retval);

#if defined(USE_THREAD) && defined(DEBUG_OTEL)
	flt_otel_tid[tid].id         = pthread_self();
	flt_otel_tid[tid].registered = true;
#endif

	/*
	 * Start the OpenTelemetry library tracer thread.  Enable HTX streams
	 * filtering.
	 */
	if (!(fconf->flags & FLT_CFG_FL_HTX)) {
		retval = OTELC_OPS(conf->instr->tracer, start);
		if (retval == OTELC_RET_ERROR)
			FLT_OTEL_ALERT("%s", conf->instr->tracer->err);

		if (retval != OTELC_RET_ERROR) {
			retval = OTELC_OPS(conf->instr->meter, start);
			if (retval == OTELC_RET_ERROR)
				FLT_OTEL_ALERT("%s", conf->instr->meter->err);
		}

		if (retval != OTELC_RET_ERROR) {
			retval = OTELC_OPS(conf->instr->logger, start);
			if (retval == OTELC_RET_ERROR)
				FLT_OTEL_ALERT("%s", conf->instr->logger->err);
		}

		if (retval != FLT_OTEL_RET_ERROR)
			fconf->flags |= FLT_CFG_FL_HTX;
	} else {
		retval = FLT_OTEL_RET_OK;
	}

	OTELC_RETURN_INT(retval);
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_ops_deinit_per_thread - per-thread deinit callback (flt_ops.deinit_per_thread)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_deinit_per_thread(struct proxy *p, struct flt_conf *fconf)
 *
 * ARGUMENTS
 *   p     - the proxy to which the filter is attached
 *   fconf - the filter configuration
 *
 * DESCRIPTION
 *   It cleans up what the init_per_thread callback have done.  It is called
 *   in the context of a thread, before exiting it.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_deinit_per_thread(struct proxy *p, struct flt_conf *fconf)
{
	OTELC_FUNC("%p, %p", p, fconf);

	OTELC_RETURN();
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_ops_attach - filter attach callback (flt_ops.attach)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_attach(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream to which the filter is being attached
 *   f - the filter instance
 *
 * DESCRIPTION
 *   It is called after a filter instance creation, when it is attached to a
 *   stream.  This happens when the stream is started for filters defined on
 *   the stream's frontend and when the backend is set for filters declared
 *   on the stream's backend.  It is possible to ignore the filter, if needed,
 *   by returning 0.  This could be useful to have conditional filtering.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 to ignore the filter,
 *   any other value otherwise.
 */
static int flt_otel_ops_attach(struct stream *s, struct filter *f)
{
	const struct flt_otel_conf *conf = FLT_OTEL_CONF(f);
	char                       *err = NULL;

	OTELC_FUNC("%p, %p", s, f);

	/* Skip attachment when the filter is globally disabled. */
	if (_HA_ATOMIC_LOAD(&(conf->instr->flag_disabled))) {
		OTELC_DBG(NOTICE, "filter '%s', type: %s (disabled)", conf->id, flt_otel_type(f));

#ifdef FLT_OTEL_USE_COUNTERS
		_HA_ATOMIC_ADD(FLT_OTEL_CONF(f)->cnt.attached + 2, 1);
#endif

		OTELC_RETURN_INT(FLT_OTEL_RET_IGNORE);
	}
	else if (_HA_ATOMIC_LOAD(&(conf->instr->rate_limit)) < FLT_OTEL_FLOAT_U32(100.0)) {
		uint32_t rnd = ha_random32();
		uint32_t rate = _HA_ATOMIC_LOAD(&(conf->instr->rate_limit));

		if (rate <= rnd) {
			OTELC_DBG(NOTICE, "filter '%s', type: %s (ignored: %u <= %u)", conf->id, flt_otel_type(f), rate, rnd);

#ifdef FLT_OTEL_USE_COUNTERS
			_HA_ATOMIC_ADD(FLT_OTEL_CONF(f)->cnt.attached + 1, 1);
#endif

			OTELC_RETURN_INT(FLT_OTEL_RET_IGNORE);
		}
	}

	OTELC_DBG(NOTICE, "filter '%s', type: %s (run)", conf->id, flt_otel_type(f));

	/* Create the per-stream runtime context. */
	f->ctx = flt_otel_runtime_context_init(s, f, &err);
	FLT_OTEL_ERR_FREE(err);
	if (f->ctx == NULL) {
		FLT_OTEL_LOG(LOG_EMERG, "failed to create context");

#ifdef FLT_OTEL_USE_COUNTERS
		_HA_ATOMIC_ADD(FLT_OTEL_CONF(f)->cnt.attached + 3, 1);
#endif

		OTELC_RETURN_INT(FLT_OTEL_RET_IGNORE);
	}

	/*
	 * AN_REQ_WAIT_HTTP and AN_RES_WAIT_HTTP analyzers can only be used
	 * in the .channel_post_analyze callback function.
	 */
	f->pre_analyzers  |= conf->instr->analyzers & ((AN_REQ_ALL & ~AN_REQ_WAIT_HTTP & ~AN_REQ_HTTP_TARPIT) | (AN_RES_ALL & ~AN_RES_WAIT_HTTP));
	f->post_analyzers |= conf->instr->analyzers & (AN_REQ_WAIT_HTTP | AN_RES_WAIT_HTTP);

#ifdef FLT_OTEL_USE_COUNTERS
	_HA_ATOMIC_ADD(FLT_OTEL_CONF(f)->cnt.attached + 0, 1);
#endif
	FLT_OTEL_LOG(LOG_INFO, "%08x %08x", f->pre_analyzers, f->post_analyzers);

#ifdef USE_OTEL_VARS
	flt_otel_vars_dump(s);
#endif
	flt_otel_http_headers_dump(&(s->req));

	OTELC_RETURN_INT(FLT_OTEL_RET_OK);
}


/***
 * NAME
 *   flt_otel_ops_stream_start - stream start callback (flt_ops.stream_start)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_stream_start(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream that is being started
 *   f - the filter instance
 *
 * DESCRIPTION
 *   It is called when a stream is started.  This callback can fail by returning
 *   a negative value.  It will be considered as a critical error by HAProxy
 *   which disabled the listener for a short time.  After the stream-start
 *   event, it initializes the idle timer in the runtime context from the
 *   precomputed minimum idle_timeout in the instrumentation configuration.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_stream_start(struct stream *s, struct filter *f)
{
	const struct flt_otel_conf      *conf = FLT_OTEL_CONF(f);
	struct flt_otel_runtime_context *rt_ctx;
	char                            *err = NULL;
	int                              retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p", s, f);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, FLT_OTEL_EVENT__STREAM_START)))
		OTELC_RETURN_INT(retval);

	/* The result of the function is ignored. */
	(void)flt_otel_event_run(s, f, NULL, FLT_OTEL_EVENT__STREAM_START, &err);

	/*
	 * Initialize the idle timer from the precomputed minimum idle_timeout
	 * in the instrumentation configuration.
	 */
	if (conf->instr->idle_timeout != 0) {
		rt_ctx = FLT_OTEL_RT_CTX(f->ctx);

		rt_ctx->idle_timeout = conf->instr->idle_timeout;
		rt_ctx->idle_exp     = tick_add(now_ms, rt_ctx->idle_timeout);

		s->req.analyse_exp = tick_first(s->req.analyse_exp, rt_ctx->idle_exp);
	}

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_ops_stream_set_backend - stream set-backend callback (flt_ops.stream_set_backend)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_stream_set_backend(struct stream *s, struct filter *f, struct proxy *be)
 *
 * ARGUMENTS
 *   s  - the stream being processed
 *   f  - the filter instance
 *   be - the backend proxy being assigned
 *
 * DESCRIPTION
 *   It is called when a backend is set for a stream.  This callback will be
 *   called for all filters attached to a stream (frontend and backend).  Note
 *   this callback is not called if the frontend and the backend are the same.
 *   It fires the on-backend-set event.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, any other value otherwise.
 */
static int flt_otel_ops_stream_set_backend(struct stream *s, struct filter *f, struct proxy *be)
{
	char *err = NULL;
	int   retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %p", s, f, be);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, FLT_OTEL_EVENT__BACKEND_SET)))
		OTELC_RETURN_INT(retval);

	OTELC_DBG(DEBUG, "backend: %s", be->id);

	(void)flt_otel_event_run(s, f, &(s->req), FLT_OTEL_EVENT__BACKEND_SET, &err);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_ops_stream_stop - stream stop callback (flt_ops.stream_stop)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_stream_stop(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream being stopped
 *   f - the filter instance
 *
 * DESCRIPTION
 *   It is called when a stream is stopped.  This callback always succeed.
 *   Anyway, it is too late to return an error.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_stream_stop(struct stream *s, struct filter *f)
{
	char *err = NULL;

	OTELC_FUNC("%p, %p", s, f);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, FLT_OTEL_EVENT__STREAM_STOP)))
		OTELC_RETURN();

	/* The result of the function is ignored. */
	(void)flt_otel_event_run(s, f, NULL, FLT_OTEL_EVENT__STREAM_STOP, &err);

	flt_otel_return_void(f, &err);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_detach - filter detach callback (flt_ops.detach)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_detach(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream from which the filter is being detached
 *   f - the filter instance
 *
 * DESCRIPTION
 *   It is called when a filter instance is detached from a stream, before its
 *   destruction.  This happens when the stream is stopped for filters defined
 *   on the stream's frontend and when the analyze ends for filters defined on
 *   the stream's backend.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_detach(struct stream *s, struct filter *f)
{
	OTELC_FUNC("%p, %p", s, f);

	OTELC_DBG(NOTICE, "filter '%s', type: %s", FLT_OTEL_CONF(f)->id, flt_otel_type(f));

	flt_otel_runtime_context_free(f);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_check_timeouts - timeout callback (flt_ops.check_timeouts)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_check_timeouts(struct stream *s, struct filter *f)
 *
 * ARGUMENTS
 *   s - the stream whose timer has expired
 *   f - the filter instance
 *
 * DESCRIPTION
 *   Timeout callback for the filter.  When the idle-timeout timer has expired,
 *   it fires the on-idle-timeout event via flt_otel_event_run() and reschedules
 *   the timer for the next interval.  It also sets the STRM_EVT_MSG pending
 *   event flag on the <s> stream so that the stream processing loop
 *   re-evaluates the message state after the timeout.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_check_timeouts(struct stream *s, struct filter *f)
{
	struct flt_otel_runtime_context *rt_ctx;
	char                            *err = NULL;

	OTELC_FUNC("%p, %p", s, f);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, -1)))
		OTELC_RETURN();

	rt_ctx = FLT_OTEL_RT_CTX(f->ctx);

	/*
	 * This callback is invoked for every timer event on the stream,
	 * not only for our idle timer.  The filter API provides no way to
	 * distinguish which timer expired, so the tick check below is the only
	 * mechanism to determine whether our idle timer is the one that fired.
	 */
	if (tick_isset(rt_ctx->idle_exp) && tick_is_expired(rt_ctx->idle_exp, now_ms)) {
		/* Fire the on-idle-timeout event. */
		(void)flt_otel_event_run(s, f, &(s->req), FLT_OTEL_EVENT__IDLE_TIMEOUT, &err);

		/* Reschedule the next idle timeout. */
		rt_ctx->idle_exp = tick_add(now_ms, rt_ctx->idle_timeout);

		/*
		 * Reset analyse_exp if it has expired before merging in the new
		 * idle tick.  Without this, tick_first() would keep returning
		 * the stale expired value, causing the stream task to wake in
		 * a tight loop.
		 */
		if (tick_is_expired(s->req.analyse_exp, now_ms))
			s->req.analyse_exp = TICK_ETERNITY;

		s->req.analyse_exp = tick_first(s->req.analyse_exp, rt_ctx->idle_exp);

		/* Force the request and response analysers to be re-evaluated. */
		s->pending_events |= STRM_EVT_MSG;
	}

	flt_otel_return_void(f, &err);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_channel_start_analyze - channel start-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_start_analyze(struct stream *s, struct filter *f, struct channel *chn)
 *
 * ARGUMENTS
 *   s   - the stream being analyzed
 *   f   - the filter instance
 *   chn - the channel on which the analyzing starts
 *
 * DESCRIPTION
 *   Channel start-analyze callback.  It registers the configured analyzers
 *   on the <chn> channel and runs the client or server session-start event
 *   depending on the channel direction.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_start_analyze(struct stream *s, struct filter *f, struct channel *chn)
{
	char *err = NULL;
	int   retval;

	OTELC_FUNC("%p, %p, %p", s, f, chn);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, (chn->flags & CF_ISRESP) ? FLT_OTEL_EVENT_RES_SERVER_SESS_START : FLT_OTEL_EVENT_REQ_CLIENT_SESS_START)))
		OTELC_RETURN_INT(FLT_OTEL_RET_OK);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));

	if (chn->flags & CF_ISRESP) {
		/* The response channel. */
		chn->analysers |= f->pre_analyzers & AN_RES_ALL;

		/* The event 'on-server-session-start'. */
		retval = flt_otel_event_run(s, f, chn, FLT_OTEL_EVENT_RES_SERVER_SESS_START, &err);

		/*
		 * WAIT is currently never returned by flt_otel_event_run(),
		 * this is kept for defensive purposes only.
		 */
		if (retval == FLT_OTEL_RET_WAIT) {
			channel_dont_read(chn);
			channel_dont_close(chn);
		}
	} else {
		/* The request channel. */
		chn->analysers |= f->pre_analyzers & AN_REQ_ALL;

		/* The event 'on-client-session-start'. */
		retval = flt_otel_event_run(s, f, chn, FLT_OTEL_EVENT_REQ_CLIENT_SESS_START, &err);
	}

	/*
	 * Data filter registration is intentionally disabled.  The http_payload
	 * and tcp_payload callbacks are debug-only stubs (registered via
	 * OTELC_DBG_IFDEF) and do not process data.
	 *
	 * register_data_filter(s, chn, f);
	 */

	/*
	 * Propagate the idle-timeout expiry to the channel so the stream task
	 * keeps waking at the configured interval.
	 */
	if (tick_isset(FLT_OTEL_RT_CTX(f->ctx)->idle_exp))
		chn->analyse_exp = tick_first(chn->analyse_exp, FLT_OTEL_RT_CTX(f->ctx)->idle_exp);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_get_event - look up an event index by analyzer bit
 *
 * SYNOPSIS
 *   static int flt_otel_get_event(uint an_bit)
 *
 * ARGUMENTS
 *   an_bit - analyzer bit to search for
 *
 * DESCRIPTION
 *   Searches the flt_otel_event_data table for the entry whose an_bit field
 *   matches <an_bit>.
 *
 * RETURN VALUE
 *   Returns the table index on success, FLT_OTEL_RET_ERROR if no match is
 *   found.
 */
static int flt_otel_get_event(uint an_bit)
{
	int i;

	for (i = 0; i < OTELC_TABLESIZE(flt_otel_event_data); i++)
		if (flt_otel_event_data[i].an_bit == an_bit)
			return i;

	return FLT_OTEL_RET_ERROR;
}


/***
 * NAME
 *   flt_otel_ops_channel_pre_analyze - channel pre-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_pre_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
 *
 * ARGUMENTS
 *   s      - the stream being analyzed
 *   f      - the filter instance
 *   chn    - the channel on which the analyzing is done
 *   an_bit - the analyzer identifier bit
 *
 * DESCRIPTION
 *   Channel pre-analyze callback.  It maps the <an_bit> analyzer bit to an
 *   event index and runs the corresponding event via flt_otel_event_run().
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_pre_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
{
	char *err = NULL;
	int   event, retval;

	OTELC_FUNC("%p, %p, %p, 0x%08x", s, f, chn, an_bit);

	event = flt_otel_get_event(an_bit);
	if (event == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(FLT_OTEL_RET_OK);
	else if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, event)))
		OTELC_RETURN_INT(FLT_OTEL_RET_OK);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s), analyzer: %s", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s), flt_otel_analyzer(an_bit));

	retval = flt_otel_event_run(s, f, chn, event, &err);

	/*
	 * WAIT is currently never returned by flt_otel_event_run(), this is
	 * kept for defensive purposes only.
	 */
	if ((retval == FLT_OTEL_RET_WAIT) && (chn->flags & CF_ISRESP)) {
		channel_dont_read(chn);
		channel_dont_close(chn);
	}

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_ops_channel_post_analyze - channel post-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_post_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
 *
 * ARGUMENTS
 *   s      - the stream being analyzed
 *   f      - the filter instance
 *   chn    - the channel on which the analyzing is done
 *   an_bit - the analyzer identifier bit
 *
 * DESCRIPTION
 *   This function, for its part, is not resumable.  It is called when a
 *   filterable analyzer finishes its processing.  So it is called once for
 *   the same analyzer.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_post_analyze(struct stream *s, struct filter *f, struct channel *chn, uint an_bit)
{
	char *err = NULL;
	int   event, retval;

	OTELC_FUNC("%p, %p, %p, 0x%08x", s, f, chn, an_bit);

	event = flt_otel_get_event(an_bit);
	if (event == FLT_OTEL_RET_ERROR)
		OTELC_RETURN_INT(FLT_OTEL_RET_OK);
	else if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, event)))
		OTELC_RETURN_INT(FLT_OTEL_RET_OK);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s), analyzer: %s", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s), flt_otel_analyzer(an_bit));

	retval = flt_otel_event_run(s, f, chn, event, &err);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_ops_channel_end_analyze - channel end-analyze callback
 *
 * SYNOPSIS
 *   static int flt_otel_ops_channel_end_analyze(struct stream *s, struct filter *f, struct channel *chn)
 *
 * ARGUMENTS
 *   s   - the stream being analyzed
 *   f   - the filter instance
 *   chn - the channel on which the analyzing ends
 *
 * DESCRIPTION
 *   Channel end-analyze callback.  It runs the client or server session-end
 *   event depending on the <chn> channel direction.  For the request channel,
 *   it also fires the server-unavailable event if response analyzers were
 *   configured but never executed.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_channel_end_analyze(struct stream *s, struct filter *f, struct channel *chn)
{
	char *err = NULL;
	int   rc, retval;

	OTELC_FUNC("%p, %p, %p", s, f, chn);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, (chn->flags & CF_ISRESP) ? FLT_OTEL_EVENT_RES_SERVER_SESS_END : FLT_OTEL_EVENT_REQ_CLIENT_SESS_END)))
		OTELC_RETURN_INT(FLT_OTEL_RET_OK);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));

	if (chn->flags & CF_ISRESP) {
		/* The response channel, event 'on-server-session-end'. */
		retval = flt_otel_event_run(s, f, chn, FLT_OTEL_EVENT_RES_SERVER_SESS_END, &err);
	} else {
		/* The request channel, event 'on-client-session-end'. */
		retval = flt_otel_event_run(s, f, chn, FLT_OTEL_EVENT_REQ_CLIENT_SESS_END, &err);

		/*
		 * In case an event using server response is defined and not
		 * executed, event 'on-server-unavailable' is called here.
		 */
		if ((FLT_OTEL_CONF(f)->instr->analyzers & AN_RES_ALL) && !(FLT_OTEL_RT_CTX(f->ctx)->analyzers & AN_RES_ALL)) {
			rc = flt_otel_event_run(s, f, chn, FLT_OTEL_EVENT_REQ_SERVER_UNAVAILABLE, &err);
			if ((retval == FLT_OTEL_RET_OK) && (rc != FLT_OTEL_RET_OK))
				retval = rc;
		}
	}

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_ops_http_headers - HTTP headers callback (flt_ops.http_headers)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
 *
 * ARGUMENTS
 *   s   - the stream being processed
 *   f   - the filter instance
 *   msg - the HTTP message whose headers are ready
 *
 * DESCRIPTION
 *   HTTP headers callback.  It fires the on-http-headers-request or
 *   on-http-headers-response event depending on the channel direction.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_http_headers(struct stream *s, struct filter *f, struct http_msg *msg)
{
	int event = (msg->chn->flags & CF_ISRESP) ? FLT_OTEL_EVENT_RES_HTTP_HEADERS : FLT_OTEL_EVENT_REQ_HTTP_HEADERS;
	char *err = NULL;
	int   retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %p", s, f, msg);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, event)))
		OTELC_RETURN_INT(retval);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(msg->chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));

	(void)flt_otel_event_run(s, f, msg->chn, event, &err);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_ops_http_payload - HTTP payload callback (flt_ops.http_payload)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_http_payload(struct stream *s, struct filter *f, struct http_msg *msg, uint offset, uint len)
 *
 * ARGUMENTS
 *   s      - the stream being processed
 *   f      - the filter instance
 *   msg    - the HTTP message containing the payload
 *   offset - the offset in the HTX message where data starts
 *   len    - the maximum number of bytes to forward
 *
 * DESCRIPTION
 *   Debug-only HTTP payload callback.  It logs the channel direction, proxy
 *   mode, offset and data length.  No actual data processing is performed.
 *
 * RETURN VALUE
 *   Returns the number of bytes to forward, or a negative value on error.
 */
static int flt_otel_ops_http_payload(struct stream *s, struct filter *f, struct http_msg *msg, uint offset, uint len)
{
	char *err = NULL;
	int   retval = len;

	OTELC_FUNC("%p, %p, %p, %u, %u", s, f, msg, offset, len);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, -1)))
		OTELC_RETURN_INT(len);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s), offset: %u, len: %u, forward: %d", flt_otel_chn_label(msg->chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s), offset, len, retval);

	/* Debug stub -- retval is always len, wakeup is never reached. */
	if (retval != len)
		task_wakeup(s->task, TASK_WOKEN_MSG);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_ops_http_end - HTTP end callback (flt_ops.http_end)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_http_end(struct stream *s, struct filter *f, struct http_msg *msg)
 *
 * ARGUMENTS
 *   s   - the stream being processed
 *   f   - the filter instance
 *   msg - the HTTP message that has ended
 *
 * DESCRIPTION
 *   HTTP end callback.  It fires the on-http-end-request or
 *   on-http-end-response event depending on the channel direction.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
static int flt_otel_ops_http_end(struct stream *s, struct filter *f, struct http_msg *msg)
{
	int event = (msg->chn->flags & CF_ISRESP) ? FLT_OTEL_EVENT_RES_HTTP_END : FLT_OTEL_EVENT_REQ_HTTP_END;
	char *err = NULL;
	int   retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %p, %p", s, f, msg);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, event)))
		OTELC_RETURN_INT(retval);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(msg->chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));

	(void)flt_otel_event_run(s, f, msg->chn, event, &err);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}


/***
 * NAME
 *   flt_otel_ops_http_reply - HTTP reply callback (flt_ops.http_reply)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_http_reply(struct stream *s, struct filter *f, short status, const struct buffer *msg)
 *
 * ARGUMENTS
 *   s      - the stream being processed
 *   f      - the filter instance
 *   status - the HTTP status code of the reply
 *   msg    - the reply message buffer, or NULL
 *
 * DESCRIPTION
 *   HTTP reply callback.  It fires the on-http-reply event when HAProxy
 *   generates an internal reply (e.g. error page or deny response).
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_http_reply(struct stream *s, struct filter *f, short status, const struct buffer *msg)
{
	char *err = NULL;

	OTELC_FUNC("%p, %p, %hd, %p", s, f, status, msg);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, FLT_OTEL_EVENT_RES_HTTP_REPLY)))
		OTELC_RETURN();

	OTELC_DBG(DEBUG, "channel: -, mode: %s (%s), status: %hd", flt_otel_pr_mode(s), flt_otel_stream_pos(s), status);

	(void)flt_otel_event_run(s, f, &(s->res), FLT_OTEL_EVENT_RES_HTTP_REPLY, &err);

	flt_otel_return_void(f, &err);

	OTELC_RETURN();
}


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_ops_http_reset - HTTP reset callback (flt_ops.http_reset)
 *
 * SYNOPSIS
 *   static void flt_otel_ops_http_reset(struct stream *s, struct filter *f, struct http_msg *msg)
 *
 * ARGUMENTS
 *   s   - the stream being processed
 *   f   - the filter instance
 *   msg - the HTTP message being reset
 *
 * DESCRIPTION
 *   Debug-only HTTP reset callback.  It logs the channel direction and proxy
 *   mode when an HTTP message is reset (e.g. due to a redirect or retry).
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
static void flt_otel_ops_http_reset(struct stream *s, struct filter *f, struct http_msg *msg)
{
	char *err = NULL;

	OTELC_FUNC("%p, %p, %p", s, f, msg);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, -1)))
		OTELC_RETURN();

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s)", flt_otel_chn_label(msg->chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s));

	flt_otel_return_void(f, &err);

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_ops_tcp_payload - TCP payload callback (flt_ops.tcp_payload)
 *
 * SYNOPSIS
 *   static int flt_otel_ops_tcp_payload(struct stream *s, struct filter *f, struct channel *chn, uint offset, uint len)
 *
 * ARGUMENTS
 *   s      - the stream being processed
 *   f      - the filter instance
 *   chn    - the channel containing the payload data
 *   offset - the offset in the buffer where data starts
 *   len    - the maximum number of bytes to forward
 *
 * DESCRIPTION
 *   Debug-only TCP payload callback.  It logs the channel direction, proxy
 *   mode, offset and data length.  No actual data processing is performed.
 *
 * RETURN VALUE
 *   Returns the number of bytes to forward, or a negative value on error.
 */
static int flt_otel_ops_tcp_payload(struct stream *s, struct filter *f, struct channel *chn, uint offset, uint len)
{
	char *err = NULL;
	int   retval = len;

	OTELC_FUNC("%p, %p, %p, %u, %u", s, f, chn, offset, len);

	if (flt_otel_is_disabled(f FLT_OTEL_DBG_ARGS(, -1)))
		OTELC_RETURN_INT(len);

	OTELC_DBG(DEBUG, "channel: %s, mode: %s (%s), offset: %u, len: %u, forward: %d", flt_otel_chn_label(chn), flt_otel_pr_mode(s), flt_otel_stream_pos(s), offset, len, retval);

	/* Debug stub -- no data processing implemented yet. */
	if (s->flags & SF_HTX) {
	} else {
	}

	/* Debug stub -- retval is always len, wakeup is never reached. */
	if (retval != len)
		task_wakeup(s->task, TASK_WOKEN_MSG);

	OTELC_RETURN_INT(flt_otel_return_int(f, &err, retval));
}

#endif /* DEBUG_OTEL */


struct flt_ops flt_otel_ops = {
	/* Callbacks to manage the filter lifecycle. */
	.init                  = flt_otel_ops_init,
	.deinit                = flt_otel_ops_deinit,
	.check                 = flt_otel_ops_check,
	.init_per_thread       = flt_otel_ops_init_per_thread,
	.deinit_per_thread     = OTELC_DBG_IFDEF(flt_otel_ops_deinit_per_thread, NULL),

	/* Stream callbacks. */
	.attach                = flt_otel_ops_attach,
	.stream_start          = flt_otel_ops_stream_start,
	.stream_set_backend    = flt_otel_ops_stream_set_backend,
	.stream_stop           = flt_otel_ops_stream_stop,
	.detach                = flt_otel_ops_detach,
	.check_timeouts        = flt_otel_ops_check_timeouts,

	/* Channel callbacks. */
	.channel_start_analyze = flt_otel_ops_channel_start_analyze,
	.channel_pre_analyze   = flt_otel_ops_channel_pre_analyze,
	.channel_post_analyze  = flt_otel_ops_channel_post_analyze,
	.channel_end_analyze   = flt_otel_ops_channel_end_analyze,

	/* HTTP callbacks. */
	.http_headers          = flt_otel_ops_http_headers,
	.http_payload          = OTELC_DBG_IFDEF(flt_otel_ops_http_payload, NULL),
	.http_end              = flt_otel_ops_http_end,
	.http_reset            = OTELC_DBG_IFDEF(flt_otel_ops_http_reset, NULL),
	.http_reply            = flt_otel_ops_http_reply,

	/* TCP callbacks. */
	.tcp_payload           = OTELC_DBG_IFDEF(flt_otel_ops_tcp_payload, NULL)
};


/* Advertise OTel support in haproxy -vv output. */
REGISTER_BUILD_OPTS("Built with OpenTelemetry support (C++ version " OTELCPP_VERSION ", C Wrapper version " OTELC_VERSION ").");

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
