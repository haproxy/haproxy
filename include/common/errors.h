/*
 * include/common/errors.h
 * Global error macros and constants
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _COMMON_ERRORS_H
#define _COMMON_ERRORS_H

/* These flags may be used in various functions which are called from within
 * loops (eg: to start all listeners from all proxies). They provide enough
 * information to let the caller decide what to do. ERR_WARN and ERR_ALERT
 * do not indicate any error, just that a message has been put in a shared
 * buffer in order to be displayed by the caller.
 */
#define ERR_NONE	0x00	/* no error, no message returned */
#define ERR_RETRYABLE	0x01	/* retryable error, may be cumulated */
#define ERR_FATAL	0x02	/* fatal error, may be cumulated */
#define ERR_ABORT	0x04	/* it's preferable to end any possible loop */
#define ERR_WARN	0x08	/* a warning message has been returned */
#define ERR_ALERT	0x10	/* an alert message has been returned */

#define ERR_CODE	(ERR_RETRYABLE|ERR_FATAL|ERR_ABORT)	/* mask */


/* These codes may be used by config parsing functions which detect errors and
 * which need to inform the upper layer about them. They are all prefixed with
 * "PE_" for "Parse Error". These codes will probably be extended, and functions
 * making use of them should be documented as such. Only code PE_NONE (zero) may
 * indicate a valid condition, all other ones must be caught as errors, event if
 * unknown by the caller. This must not be used to forward warnings.
 */
enum {
	PE_NONE = 0,      /* no error */
	PE_ENUM_OOR,      /* enum data out of allowed range */
	PE_EXIST,         /* trying to create something which already exists */
	PE_ARG_MISSING,   /* mandatory argument not provided */
	PE_ARG_NOT_USED,  /* argument provided cannot be used */
	PE_ARG_INVC,      /* invalid char in argument (pointer not provided) */
	PE_ARG_INVC_PTR,  /* invalid char in argument (pointer provided) */
	PE_ARG_NOT_FOUND, /* argument references something not found */
};

#endif /* _COMMON_ERRORS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
