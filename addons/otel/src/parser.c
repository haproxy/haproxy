/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


#ifdef OTELC_DBG_MEM
static struct otelc_dbg_mem_data dbg_mem_data[1000000];
static struct otelc_dbg_mem      dbg_mem;
#endif


/***
 * NAME
 *   flt_otel_parse - main filter parser entry point
 *
 * SYNOPSIS
 *   static int flt_otel_parse(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf, char **err, void *private)
 *
 * ARGUMENTS
 *   args    - configuration line arguments array
 *   cur_arg - pointer to the current argument index
 *   px      - proxy instance owning the filter
 *   fconf   - filter configuration structure to populate
 *   err     - indirect pointer to error message string
 *   private - unused private data pointer
 *
 * DESCRIPTION
 *   Main filter parser entry point, registered for the "otel" filter keyword.
 *   Verifies that insecure-fork-wanted is enabled, then parses the filter ID
 *   and configuration file path from the HAProxy configuration line.  If no
 *   filter ID is specified, the default ID is used.
 *
 * RETURN VALUE
 *   Returns ERR_NONE (== 0) in case of success,
 *   or a combination of ERR_* flags if an error is encountered.
 */
static int flt_otel_parse(char **args, int *cur_arg, struct proxy *px, struct flt_conf *fconf, char **err, void *private)
{
	int retval = ERR_NONE;

	OTELC_FUNC("%p, %p, %p, %p, %p:%p, %p", args, cur_arg, px, fconf, OTELC_DPTR_ARGS(err), private);

	OTELC_DBG_IFDEF(otelc_dbg_level = FLT_OTEL_DEBUG_LEVEL, );

#ifdef OTELC_DBG_MEM
	/* Initialize the debug memory tracker before the first allocation. */
	FLT_OTEL_RUN_ONCE(
		if (otelc_dbg_mem_init(&dbg_mem, dbg_mem_data, OTELC_TABLESIZE(dbg_mem_data)) == -1)
			OTELC_RETURN_INT(retval);
	);
#endif

	OTELC_RETURN_INT(retval);
}


/* Declare the filter parser for FLT_OTEL_OPT_NAME keyword. */
static struct flt_kw_list flt_kws = { FLT_OTEL_SCOPE, { }, {
		{ FLT_OTEL_OPT_NAME, flt_otel_parse, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &flt_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
