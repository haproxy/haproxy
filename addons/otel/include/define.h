/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_DEFINE_H_
#define _OTEL_DEFINE_H_

/* Execute a statement exactly once across all invocations. */
#define FLT_OTEL_RUN_ONCE(f)         do { static bool _f = 1; if (_f) { _f = 0; { f; } } } while (0)

#endif /* _OTEL_DEFINE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
