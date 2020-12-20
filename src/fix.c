/*
 * Financial Information eXchange Protocol
 *
 * Copyright 2020 Baptiste Assmann <bedis9@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/intops.h>
#include <haproxy/fix.h>
/*
 * Return the corresponding numerical tag id if <str> looks like a valid FIX
 * protocol tag ID. Otherwise, 0 is returned (0 is an invalid id).
 *
 * If <version> is given, it must be one of a defined FIX version string (see
 * FIX_X_Y macros). In this case, the function will also check tag ID ranges. If
 * no <version> is provided, any strictly positive integer is valid.
 *
 * tag ID range depends on FIX protocol version:
 *    - FIX.4.0:    1-140
 *    - FIX.4.1:    1-211
 *    - FIX.4.2:    1-446
 *    - FIX.4.3:    1-659
 *    - FIX.4.4:    1-956
 *    - FIX.5.0:    1-1139
 *    - FIX.5.0SP1: 1-1426
 *    - FIX.5.0SP2: 1-1621
 * range 10000 to 19999 is for "user defined tags"
 */
unsigned int fix_check_id(const struct ist str, const struct ist version) {
	const char *s, *end;
	unsigned int ret;

	s = istptr(str);
	end = istend(str);
	ret = read_uint(&s, end);

	/* we did not consume all characters from <str>, this is an error */
	if (s != end)
		return 0;

	/* field ID can't be 0 */
	if (ret == 0)
		return 0;

	/* we can leave now if version was not provided */
	if (!isttest(version))
		return ret;

	/* we can leave now if this is a "user defined tag id" */
	if (ret >= 10000 && ret <= 19999)
		return ret;

	/* now perform checking per FIX version */
	if (istissame(FIX_4_0, version) && (ret <= 140))
		return ret;
	else if (istissame(FIX_4_1, version) && (ret <= 211))
		return ret;
	else if (istissame(FIX_4_2, version) && (ret <= 446))
		return ret;
	else if (istissame(FIX_4_3, version) && (ret <= 659))
		return ret;
	else if (istissame(FIX_4_4, version) && (ret <= 956))
		return ret;
	/* version string is the same for all 5.0 versions, so we can only take
	 * into consideration the biggest range
	 */
	else if (istissame(FIX_5_0, version) && (ret <= 1621))
		return ret;

	return 0;
}

/*
 * Parse a FIX message <msg> and performs following sanity checks:
 *
 *   - checks tag ids and values are not empty
 *   - checks tag ids are numerical value
 *   - checks the first tag is BeginString with a valid version
 *   - checks the second tag is BodyLength with the right body length
 *   - checks the third tag is MsgType
 *   - checks the last tag is CheckSum with a valid checksum
 *
 * Returns:
 *  FIX_INVALID_MESSAGE if the message is invalid
 *  FIX_NEED_MORE_DATA  if we need more data to fully validate the message
 *  FIX_VALID_MESSAGE   if the message looks valid
 */
int fix_validate_message(const struct ist msg)
{
	struct ist parser, version;
	unsigned int tagnum, bodylen;
	unsigned char checksum;
	char *body;
	int ret = FIX_INVALID_MESSAGE;

	if (istlen(msg) < FIX_MSG_MINSIZE) {
		ret = FIX_NEED_MORE_DATA;
		goto end;
	}

	/* parsing the whole message to compute the checksum and check all tag
	 * ids are properly set. Here we are sure to have the 2 first tags. Thus
	 * the version and the body length can be checked.
	 */
	parser = msg;
	version = IST_NULL;
	checksum = tagnum = bodylen = 0;
	body = NULL;
	while (istlen(parser) > 0) {
		struct ist tag, value;
		unsigned int tagid;
		const char *p, *end;

		/* parse the tag ID and its value and perform first sanity checks */
		value = iststop(istfind(parser, '='), FIX_DELIMITER);

		/* end of value not found */
		if (istend(value) == istend(parser)) {
			ret = FIX_NEED_MORE_DATA;
			goto end;
		}
		/* empty tag or empty value are forbidden */
		if (istptr(parser) == istptr(value) ||!istlen(value))
			goto end;

		/* value points on '='. get the tag and skip '=' */
		tag = ist2(istptr(parser), istptr(value) - istptr(parser));
		value = istnext(value);

		/* Check the tag id */
		tagid = fix_check_id(tag, version);
		if (!tagid)
			goto end;
		tagnum++;

		if (tagnum == 1) {
			/* the first tag must be BeginString */
			if (tagid != FIX_TAG_BeginString)
				goto end;

			version = fix_version(value);
			if (!isttest(version))
				goto end;
		}
		else if (tagnum == 2) {
			/* the second tag must be bodyLength */
			if (tagid != FIX_TAG_BodyLength)
				goto end;

			p = istptr(value);
			end = istend(value);
			bodylen = read_uint(&p, end);

			/* we did not consume all characters from <str> or no body, this is an error.
			 * There is at least the message type in the body.
			 */
			if (p != end || !bodylen)
				goto end;

			body = istend(value) + 1;
		}
		else if (tagnum == 3) {
			/* the third tag must be MsgType */
			if (tagid != FIX_TAG_MsgType)
				goto end;
		}
		else if (tagnum > 3 && tagid == FIX_TAG_CheckSum) {
			/* CheckSum tag should be the last one and is not taken into account
			 * to compute the checksum itself and the body length. The value is
			 * a three-octet representation of the checksum decimal value.
			 */
			if (bodylen != istptr(parser) - body)
				goto end;

			if (istlen(value) != 3)
				goto end;
			if (checksum != strl2ui(istptr(value), istlen(value)))
				goto end;

			/* End of the message, exit from the loop */
			ret = FIX_VALID_MESSAGE;
			goto end;
		}

		/* compute checksum of tag=value<delim> */
		for (p = istptr(tag) ; p < istend(tag) ; ++p)
			checksum += *p;
		checksum += '=';
		for (p = istptr(value) ; p < istend(value) ; ++p)
			checksum += *p;
		checksum += FIX_DELIMITER;

		/* move the parser after the value and its delimiter */
		parser = istadv(parser, istlen(tag) + istlen(value) + 2);
	}

	if (body) {
		/* We start to read the body but we don't reached the checksum tag */
		ret = FIX_NEED_MORE_DATA;
	}

  end:
	return ret;
}


/*
 * Iter on a FIX message <msg> and return the value of <tagid>.
 *
 * Returns the corresponding value if <tagid> is found. If <tagid> is not found
 * because more data are required, the message with a length set to 0 is
 * returned. If <tagid> is not found in the message or if the message is
 * invalid, IST_NULL is returned.
 *
 * Note: Only simple sanity checks are performed on tags and values (not empty).
 *
 * the tag looks like
 *   <tagid>=<value>FIX_DELIMITER with <tag> and <value> not empty
 */
struct ist fix_tag_value(const struct ist msg, unsigned int tagid)
{
	struct ist parser, t, v;
	unsigned int id;

	parser = msg;
	while (istlen(parser) > 0) {
		v  = iststop(istfind(parser, '='), FIX_DELIMITER);

		/* delimiter not found, need more data */
		if (istend(v) == istend(parser))
			break;

		/* empty tag or empty value, invalid */
		if (istptr(parser) == istptr(v) || !istlen(v))
			goto not_found_or_invalid;

		t = ist2(istptr(parser), istptr(v) - istptr(parser));
		v = istnext(v);

		id = fix_check_id(t, IST_NULL);
		if (!id)
			goto not_found_or_invalid;
		if (id == tagid) {
			/* <tagId> found, return the corrsponding value */
			return v;
		}

		/* CheckSum tag is the last one, no <tagid> found */
		if (id == FIX_TAG_CheckSum)
			goto not_found_or_invalid;

		parser = istadv(parser, istlen(t) + istlen(v) + 2);
	}
	/* not enough data to find <tagid> */
	return ist2(istptr(msg), 0);

  not_found_or_invalid:
	return IST_NULL;
}
