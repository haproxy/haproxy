/*
 * include/haproxy/fix.h
 * This file contains functions and macros declarations for FIX protocol decoding.
 *
 * Copyright 2020 Baptiste Assmann <bedis9@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _HAPROXY_FIX_H
#define _HAPROXY_FIX_H

#include <import/ist.h>

#include <haproxy/fix-t.h>
#include <haproxy/tools.h>

unsigned int fix_check_id(const struct ist str, const struct ist version);
int fix_validate_message(const struct ist msg);
struct ist fix_tag_value(const struct ist msg, unsigned int tagid);

/*
 * Return the FIX version string (one of FIX_X_Y macros) corresponding to
 * <str> or IST_NULL if not found.
 */
static inline struct ist fix_version(const struct ist str)
{
	/* 7 is the minimal size for the FIX version string */
	if (istlen(str) < 7)
		return IST_NULL;

	if (isteq(FIX_4_0, str))
		return FIX_4_0;
	else if (isteq(FIX_4_1, str))
		return FIX_4_1;
	else if (isteq(FIX_4_2, str))
		return FIX_4_2;
	else if (isteq(FIX_4_3, str))
		return FIX_4_3;
	else if (isteq(FIX_4_4, str))
		return FIX_4_4;
	else if (isteq(FIX_5_0, str))
		return FIX_5_0;

	return IST_NULL;
}

/*
 * Return the FIX tag ID corresponding to <tag> if one found or 0 if not.
 *
 * full list of tag ID available here, just in case we need to support
 * more "string" equivalent in the future:
 *   https://www.onixs.biz/fix-dictionary/4.2/fields_by_tag.html
 */
static inline unsigned int fix_tagid(const struct ist tag)
{
	unsigned id = fix_check_id(tag, IST_NULL);

	if (id)
		return id;

	else if (isteqi(tag, ist("MsgType")))
		return FIX_TAG_MsgType;
	else if (isteqi(tag, ist("CheckSum")))
		return FIX_TAG_CheckSum;
	else if (isteqi(tag, ist("BodyLength")))
		return FIX_TAG_BodyLength;
	else if (isteqi(tag, ist("TargetComID")))
		return FIX_TAG_TargetComID;
	else if (isteqi(tag, ist("BeginString")))
		return FIX_TAG_BeginString;
	else if (isteqi(tag, ist("SenderComID")))
		return FIX_TAG_SenderComID;

	return 0;
}

#endif /* _HAPROXY_FIX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
