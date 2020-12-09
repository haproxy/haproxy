/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef _OPENTRACING_DEFINE_H_
#define _OPENTRACING_DEFINE_H_

#define FLT_OT_DEREF(a,m,v)        (((a) != NULL) ? (a)->m : (v))
#define FLT_OT_DDEREF(a,m,v)       ((((a) != NULL) && (*(a) != NULL)) ? (*(a))->m : (v))
#define FLT_OT_TABLESIZE(a)        (sizeof(a) / sizeof((a)[0]))
#define FLT_OT_IN_RANGE(v,a,b)     (((v) >= (a)) && ((v) <= (b)))
#define FLT_OT_DPTR_ARGS(a)        (a), ((a) == NULL) ? NULL : *(a)
#define FLT_OT_ARG_ISVALID(n)      ((args[n] != NULL) && *args[n])
#define FLT_OT_TV_UDIFF(a,b)       (((b)->tv_sec - (a)->tv_sec) * 1000000 + (b)->tv_usec - (a)->tv_usec)
#define FLT_OT_U32_FLOAT(a,b)      ((a) * (double)(b) / UINT32_MAX)
#define FLT_OT_FLOAT_U32(a,b)      ((uint32_t)((a) / (double)(b) * UINT32_MAX + 0.5))

#define FLT_OT_STR_DASH_72         "------------------------------------------------------------------------"
#define FLT_OT_STR_DASH_78         FLT_OT_STR_DASH_72 "------"
#define FLT_OT_STR_FLAG_YN(a)      (a) ? "yes" : "no"

#define FLT_OT_STR_SIZE(a)         (sizeof(a) - 1)
#define FLT_OT_STR_ADDRSIZE(a)     (a), FLT_OT_STR_SIZE(a)
#define FLT_OT_STR_ISVALID(a)      (((a) != NULL) && (*(a) != '\0'))
#define FLT_OT_STR_CMP(S,s,l)      (((l) == FLT_OT_STR_SIZE(S)) && (memcmp((s), FLT_OT_STR_ADDRSIZE(S)) == 0))
#define FLT_OT_STR_ELLIPSIS(a,n)   do { if ((a) != NULL) { if ((n) > 0) (a)[(n) - 1] = '\0'; if ((n) > 3) (a)[(n) - 2] = (a)[(n) - 3] = (a)[(n) - 4] = '.'; } } while (0)
#define FLT_OT_NIBBLE_TO_HEX(a)    ((a) + (((a) < 10) ? '0' : ('a' - 10)))

#define FLT_OT_FREE(a)             do { if ((a) != NULL) OTC_DBG_FREE(a); } while (0)
#define FLT_OT_FREE_VOID(a)        do { if ((a) != NULL) OTC_DBG_FREE((void *)(a)); } while (0)
#define FLT_OT_FREE_CLEAR(a)       do { if ((a) != NULL) { OTC_DBG_FREE(a); (a) = NULL; } } while (0)
#define FLT_OT_STRDUP(s)           OTC_DBG_STRDUP(s)
#define FLT_OT_STRNDUP(s,n)        OTC_DBG_STRNDUP((s), (n))
#define FLT_OT_CALLOC(n,e)         OTC_DBG_CALLOC((n), (e))
#define FLT_OT_MALLOC(s)           OTC_DBG_MALLOC((s))
#define FLT_OT_MEMINFO()           OTC_DBG_MEMINFO()

#define FLT_OT_RUN_ONCE(f)         do { static bool __f = 1; if (__f) { __f = 0; f; } } while (0)

#define FLT_OT_LIST_ISVALID(a)     (((a) != NULL) && ((a)->n != NULL) && ((a)->p != NULL))
#define FLT_OT_LIST_DEL(a)         do { if (FLT_OT_LIST_ISVALID(a)) LIST_DEL(a); } while (0)
#define FLT_OT_LIST_DESTROY(t,h)                                                  \
	do {                                                                      \
		struct flt_ot_conf_##t *_ptr, *_back;                             \
                                                                                  \
		if (!FLT_OT_LIST_ISVALID(h) || LIST_ISEMPTY(h))                   \
			break;                                                    \
                                                                                  \
		FLT_OT_DBG(2, "- deleting " #t " list %s", flt_ot_list_debug(h)); \
                                                                                  \
		list_for_each_entry_safe(_ptr, _back, (h), list)                  \
			flt_ot_conf_##t##_free(&_ptr);                            \
	} while (0)

#define FLT_OT_BUFFER_THR(b,m,n,p)                \
	static THREAD_LOCAL char    b[m][n];      \
	static THREAD_LOCAL size_t  __idx = 0;    \
	char                       *p = b[__idx]; \
	__idx = (__idx + 1) % (m)

#define FLT_OT_ERR(f, ...)                                      \
	do {                                                    \
		if ((err != NULL) && (*err == NULL))            \
			(void)memprintf(err, f, ##__VA_ARGS__); \
	} while (0)
#define FLT_OT_ERR_APPEND(f, ...)                               \
	do {                                                    \
		if (err != NULL)                                \
			(void)memprintf(err, f, ##__VA_ARGS__); \
	} while (0)
#define FLT_OT_ERR_FREE(p)                                                  \
	do {                                                                \
		if ((p) == NULL)                                            \
			break;                                              \
                                                                            \
		FLT_OT_DBG(0, "%s:%d: ERROR: %s", __func__, __LINE__, (p)); \
		FLT_OT_FREE_CLEAR(p);                                       \
	} while (0)

#endif /* _OPENTRACING_DEFINE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
