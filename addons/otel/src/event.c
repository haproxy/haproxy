/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


/* Event data table built from the X-macro list. */
#define FLT_OTEL_EVENT_DEF(a,b,c,d,e,f)   { AN_##b##_##a, OTELC_STRINGIFY_ARG(AN_##b##_##a), SMP_OPT_DIR_##b, SMP_VAL_FE_##c, SMP_VAL_BE_##d, e, f },
const struct flt_otel_event_data flt_otel_event_data[FLT_OTEL_EVENT_MAX] = { FLT_OTEL_EVENT_DEFINES };
#undef FLT_OTEL_EVENT_DEF


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
