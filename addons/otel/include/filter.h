/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_FILTER_H_
#define _OTEL_FILTER_H_

/* Return codes for OTel filter operations. */
enum FLT_OTEL_RET_enum {
	FLT_OTEL_RET_ERROR  = -1,
	FLT_OTEL_RET_WAIT   = 0,
	FLT_OTEL_RET_IGNORE = 0,
	FLT_OTEL_RET_OK     = 1,
};


extern const char *otel_flt_id;

#endif /* _OTEL_FILTER_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
