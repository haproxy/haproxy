#include <string.h>
#include <stdio.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/net_helper.h>
#include <haproxy/sample.h>

/*****************************************************/
/* Converters used to process Ethernet frame headers */
/*****************************************************/

/* returns only the data part of an input ethernet frame header, skipping any
 * possible VLAN header. This is typically used to return the beginning of the
 * IP packet.
 */
static int sample_conv_eth_data(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t idx;

	for (idx = 12; idx + 2 < smp->data.u.str.data; idx += 4) {
		if (read_n16(smp->data.u.str.area + idx) != 0x8100) {
			smp->data.u.str.area += idx + 2;
			smp->data.u.str.data -= idx + 2;
			return 1;
		}
	}
	/* incomplete header */
	return 0;
}

/* returns the 6 bytes of MAC DST address of an input ethernet frame header */
static int sample_conv_eth_dst(const struct arg *arg_p, struct sample *smp, void *private)
{

	if (smp->data.u.str.data < 6)
		return 0;

	smp->data.u.str.data = 6; // output length is 6
	return 1;
}

/* returns only the ethernet header for an input ethernet frame header,
 * including any possible VLAN headers, but stopping before data.
 */
static int sample_conv_eth_hdr(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t idx;

	for (idx = 12; idx + 2 < smp->data.u.str.data; idx += 4) {
		if (read_n16(smp->data.u.str.area + idx) != 0x8100) {
			smp->data.u.str.data = idx + 2;
			return 1;
		}
	}
	/* incomplete header */
	return 0;
}

/* returns the ethernet protocol of an input ethernet frame header, skipping
 * any VLAN tag.
 */
static int sample_conv_eth_proto(const struct arg *arg_p, struct sample *smp, void *private)
{
	ushort proto;
	size_t idx;

	for (idx = 12; idx + 2 < smp->data.u.str.data; idx += 4) {
		proto = read_n16(smp->data.u.str.area + idx);
		if (proto != 0x8100) {
			smp->data.u.sint = proto;
			smp->data.type = SMP_T_SINT;
			smp->flags &= ~SMP_F_CONST;
			return 1;
		}
	}
	/* incomplete header */
	return 0;
}

/* returns the 6 bytes of MAC SRC address of an input ethernet frame header */
static int sample_conv_eth_src(const struct arg *arg_p, struct sample *smp, void *private)
{

	if (smp->data.u.str.data < 12)
		return 0;

	smp->data.u.str.area += 6; // src is at address 6
	smp->data.u.str.data  = 6; // output length is 6
	return 1;
}

/* returns the last VLAN ID seen in an input ethernet frame header, if any.
 * Note that VLAN ID 0 is considered as absence of VLAN.
 */
static int sample_conv_eth_vlan(const struct arg *arg_p, struct sample *smp, void *private)
{
	ushort vlan = 0;
	size_t idx;

	for (idx = 12; idx + 2 < smp->data.u.str.data; idx += 4) {
		if (read_n16(smp->data.u.str.area + idx) != 0x8100) {
			smp->data.u.sint = vlan;
			smp->data.type = SMP_T_SINT;
			smp->flags &= ~SMP_F_CONST;
			return !!vlan;
		}
		if (idx + 4 < smp->data.u.str.data)
			break;

		vlan = read_n16(smp->data.u.str.area + idx + 2) & 0xfff;
	}
	/* incomplete header */
	return 0;
}

/*******************************************************/
/* Converters used to process IPv4/IPv6 packet headers */
/*******************************************************/

/* returns the total header length for the input IP packet header (v4 or v6),
 * including all extensions if any. It corresponds to the length to skip to
 * find the TCP or UDP header. If data are missing or unparsable, it returns
 * 0.
 */
static size_t ip_header_length(const struct sample *smp)
{
	size_t len;
	uchar next;
	uchar ver;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		len = (smp->data.u.str.area[0] & 0xF) * 4;
		if (smp->data.u.str.data < len)
			return 0;
	}
	else if (ver == 6) {
		if (smp->data.u.str.data < 40)
			return 0;

		len = 40;
		next = smp->data.u.str.area[6];

		while (next != 6 && next != 17) {
			if (smp->data.u.str.data < len + 2)
				return 0;
			next = smp->data.u.str.area[len];
			len += (uchar)smp->data.u.str.area[len + 1] * 8 + 8;
		}

		if (smp->data.u.str.data < len)
			return 0;
	}
	else {
		return 0;
	}

	return len;
}

/* returns the payload following the input IP packet header (v4 or v6) skipping
 * all extensions if any. For IPv6, it returns the TCP or UDP next header.
 */
static int sample_conv_ip_data(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len;

	len = ip_header_length(smp);
	if (!len)
		return 0;

	/* advance buffer by <len> */
	smp->data.u.str.area += len;
	smp->data.u.str.data -= len;
	return 1;
}

/* returns the DF (don't fragment) flag from an IPv4 header, as 0 or 1. The
 * value is always one for IPv6 since DF is implicit.
 */
static int sample_conv_ip_df(const struct arg *arg_p, struct sample *smp, void *private)
{
	uchar ver;
	uchar df;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		if (smp->data.u.str.data < 6)
			return 0;
		df = !!(smp->data.u.str.area[6] & 0x40);
	}
	else if (ver == 6) {
		df = 1;
	}
	else {
		return 0;
	}

	smp->data.u.sint = df;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the IP DST address found in an input IP packet header (v4 or v6). */
static int sample_conv_ip_dst(const struct arg *arg_p, struct sample *smp, void *private)
{
	uchar ver;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		if (smp->data.u.str.data < 20)
			return 0;

                smp->data.u.ipv4.s_addr = read_u32(smp->data.u.str.area + 16);
                smp->data.type = SMP_T_IPV4;
	}
	else if (ver == 6) {
		if (smp->data.u.str.data < 40)
			return 0;

                memcpy(&smp->data.u.ipv6, smp->data.u.str.area + 24, 16);
                smp->data.type = SMP_T_IPV6;
	}
	else {
		return 0;
	}

	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the IP header only for an input IP packet header (v4 or v6), including
 * all extensions if any. For IPv6, it includes every extension before TCP/UDP.
 */
static int sample_conv_ip_hdr(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len;

	len = ip_header_length(smp);
	if (!len)
		return 0;

	/* truncate buffer to <len> */
	smp->data.u.str.data = len;
	return 1;
}

/* returns the upper layer protocol number (TCP/UDP) for an input IP packet
 * header (v4 or v6).
 */
static int sample_conv_ip_proto(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len;
	uchar next;
	uchar ver;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		if (smp->data.u.str.data < 10)
			return 0;
		next = smp->data.u.str.area[9];
	}
	else if (ver == 6) {
		/* skip all extensions */
		if (smp->data.u.str.data < 40)
			return 0;

		len = 40;
		next = smp->data.u.str.area[6];

		while (next != 6 && next != 17) {
			if (smp->data.u.str.data < len + 2)
				return 0;
			next = smp->data.u.str.area[len];
			len += (uchar)smp->data.u.str.area[len + 1] * 8 + 8;
		}

		if (smp->data.u.str.data < len)
			return 0;
	}
	else {
		return 0;
	}

	/* protocol number is in <next> */
	smp->data.u.sint = next;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the IP SRC address found in an input IP packet header (v4 or v6). */
static int sample_conv_ip_src(const struct arg *arg_p, struct sample *smp, void *private)
{
	uchar ver;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		if (smp->data.u.str.data < 20)
			return 0;

                smp->data.u.ipv4.s_addr = read_u32(smp->data.u.str.area + 12);
                smp->data.type = SMP_T_IPV4;
	}
	else if (ver == 6) {
		if (smp->data.u.str.data < 40)
			return 0;

                memcpy(&smp->data.u.ipv6, smp->data.u.str.area + 8, 16);
                smp->data.type = SMP_T_IPV6;
	}
	else {
		return 0;
	}

	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the IP TOS/TC field found in an input IP packet header (v4 or v6). */
static int sample_conv_ip_tos(const struct arg *arg_p, struct sample *smp, void *private)
{
	uchar ver;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		/* TOS field is at offset 1 */
		if (smp->data.u.str.data < 2)
			return 0;

		smp->data.u.sint = (uchar)smp->data.u.str.area[1];
	}
	else if (ver == 6) {
		/* TOS field is between offset 0 and 1 */
		if (smp->data.u.str.data < 2)
			return 0;

		smp->data.u.sint = (uchar)(read_n16(smp->data.u.str.area) >> 4);
	}
	else {
		return 0;
	}

	/* OK we have the value in data.u.sint */
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the IP TTL/HL field found in an input IP packet header (v4 or v6). */
static int sample_conv_ip_ttl(const struct arg *arg_p, struct sample *smp, void *private)
{
	uchar ver;

	if (smp->data.u.str.data < 1)
		return 0;

	ver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ver == 4) {
		if (smp->data.u.str.data < 20)
			return 0;

		smp->data.u.sint = (uchar)smp->data.u.str.area[8];
	}
	else if (ver == 6) {
		if (smp->data.u.str.data < 40)
			return 0;

		smp->data.u.sint = (uchar)smp->data.u.str.area[7];
	}
	else {
		return 0;
	}

	/* OK we have the value in data.u.sint */
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the IP version found in an input IP packet header (v4 or v6). */
static int sample_conv_ip_ver(const struct arg *arg_p, struct sample *smp, void *private)
{
	if (smp->data.u.str.data < 1)
		return 0;

	smp->data.u.sint = (uchar)smp->data.u.str.area[0] >> 4;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "eth.data",           sample_conv_eth_data,           0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.dst",            sample_conv_eth_dst,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.hdr",            sample_conv_eth_hdr,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.proto",          sample_conv_eth_proto,          0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "eth.src",            sample_conv_eth_src,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.vlan",           sample_conv_eth_vlan,           0,      NULL,      SMP_T_BIN,  SMP_T_SINT },

	{ "ip.data",            sample_conv_ip_data,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "ip.df",              sample_conv_ip_df,              0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.dst",             sample_conv_ip_dst,             0,      NULL,      SMP_T_BIN,  SMP_T_ADDR },
	{ "ip.hdr",             sample_conv_ip_hdr,             0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "ip.proto",           sample_conv_ip_proto,           0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.src",             sample_conv_ip_src,             0,      NULL,      SMP_T_BIN,  SMP_T_ADDR },
	{ "ip.tos",             sample_conv_ip_tos,             0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.ttl",             sample_conv_ip_ttl,             0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.ver",             sample_conv_ip_ver,             0,      NULL,      SMP_T_BIN,  SMP_T_SINT },

	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
