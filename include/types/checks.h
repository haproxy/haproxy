/*
 * Health-checks.
 *
 * Copyright 2008-2009 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

/* check status */
enum {
	HCHK_STATUS_UNKNOWN	 = 0,	/* Unknown */
	HCHK_STATUS_INI,		/* Initializing */
	HCHK_STATUS_START,		/* Check started - SPECIAL STATUS */

	/* Below we have finished checks */
	HCHK_STATUS_CHECKED,		/* DUMMY STATUS */

	HCHK_STATUS_HANA,		/* Health analyze detected enough consecutive errors */

	HCHK_STATUS_SOCKERR,		/* Socket error */

	HCHK_STATUS_L4OK,		/* L4 check passed, for example tcp connect */
	HCHK_STATUS_L4TOUT,		/* L4 timeout */
	HCHK_STATUS_L4CON,		/* L4 connection problem, for example: */
					/*  "Connection refused" (tcp rst) or "No route to host" (icmp) */

	HCHK_STATUS_L6OK,		/* L6 check passed */
	HCHK_STATUS_L6TOUT,		/* L6 (SSL) timeout */
	HCHK_STATUS_L6RSP,		/* L6 invalid response - protocol error */

	HCHK_STATUS_L7TOUT,		/* L7 (HTTP/SMTP) timeout */
	HCHK_STATUS_L7RSP,		/* L7 invalid response - protocol error */

	/* Below we have layer 5-7 data available */
	HCHK_STATUS_L57DATA,		/* DUMMY STATUS */
	HCHK_STATUS_L7OKD,		/* L7 check passed */
	HCHK_STATUS_L7OKCD,		/* L7 check conditionally passed */
	HCHK_STATUS_L7STS,		/* L7 response error, for example HTTP 5xx */

	HCHK_STATUS_SIZE
};


/* health status for response tracking */
enum {
	HANA_STATUS_UNKNOWN	= 0,

	HANA_STATUS_L4_OK,		/* L4 successful connection */
	HANA_STATUS_L4_ERR,		/* L4 unsuccessful connection */

	HANA_STATUS_HTTP_OK,		/* Correct http response */
	HANA_STATUS_HTTP_STS,		/* Wrong http response, for example HTTP 5xx */
	HANA_STATUS_HTTP_HDRRSP,	/* Invalid http response (headers) */
	HANA_STATUS_HTTP_RSP,		/* Invalid http response */

	HANA_STATUS_HTTP_READ_ERROR,	/* Read error */
	HANA_STATUS_HTTP_READ_TIMEOUT,	/* Read timeout */
	HANA_STATUS_HTTP_BROKEN_PIPE,	/* Unexpected close from server */

	HANA_STATUS_SIZE
};

enum {
	HANA_ONERR_UNKNOWN	= 0,

	HANA_ONERR_FASTINTER,		/* Force fastinter*/
	HANA_ONERR_FAILCHK,		/* Simulate a failed check */
	HANA_ONERR_SUDDTH,		/* Enters sudden death - one more failed check will mark this server down */
	HANA_ONERR_MARKDWN,		/* Mark this server down, now! */
};

enum {
	HANA_ONMARKEDDOWN_NONE	= 0,
	HANA_ONMARKEDDOWN_SHUTDOWNSESSIONS,	/* Shutdown peer sessions */
};

enum {
	HANA_ONMARKEDUP_NONE	= 0,
	HANA_ONMARKEDUP_SHUTDOWNBACKUPSESSIONS,	/* Shutdown peer sessions */
};

enum {
	HANA_OBS_NONE		= 0,

	HANA_OBS_LAYER4,		/* Observe L4 - for example tcp */
	HANA_OBS_LAYER7,		/* Observe L7 - for example http */

	HANA_OBS_SIZE
};

struct check_status {
	short result;			/* one of SRV_CHK_* */
	char *info;			/* human readable short info */
	char *desc;			/* long description */
};

struct analyze_status {
	char *desc;				/* description */
	unsigned char lr[HANA_OBS_SIZE];	/* result for l4/l7: 0 = ignore, 1 - error, 2 - OK */
};
