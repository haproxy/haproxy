/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_CLI_H_
#define _OTEL_CLI_H_

#define FLT_OTEL_CLI_CMD                 "flt-otel"

#define FLT_OTEL_CLI_LOGGING_OFF         "off"
#define FLT_OTEL_CLI_LOGGING_ON          "on"
#define FLT_OTEL_CLI_LOGGING_NOLOGNORM   "dontlog-normal"
#define FLT_OTEL_CLI_LOGGING_STATE(a)    (((a) & FLT_OTEL_LOGGING_ON) ? (((a) & FLT_OTEL_LOGGING_NOLOGNORM) ? "enabled, " FLT_OTEL_CLI_LOGGING_NOLOGNORM : "enabled") : "disabled")

#define FLT_OTEL_CLI_MSG_CAT(a)          (((a) == NULL) ? "" : (a)), (((a) == NULL) ? "" : "\n")


/* Register CLI keywords for the OTel filter. */
void flt_otel_cli_init(void);

#endif /* _OTEL_CLI_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
