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

/******************************************/
/* Converters used to process TCP headers */
/******************************************/

/* returns the TCP header length in bytes if complete, otherwise zero */
static int tcp_fullhdr_length(const struct sample *smp)
{
	size_t ofs;

	if (smp->data.u.str.data < 20)
		return 0;

	/* check that header is complete */
	ofs = ((uchar)smp->data.u.str.area[12] >> 4) * 4;
	if (ofs < 20 || smp->data.u.str.data < ofs)
		return 0;
	return ofs;
}

/* returns the offset in the input TCP header where option kind <opt> is first
 * seen, otherwise 0 if not found. NOP and END cannot be searched.
 */
static size_t tcp_fullhdr_find_opt(const struct sample *smp, uint8_t opt)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t next = 20, curr;

	while ((curr = next) < len) {
		if (smp->data.u.str.area[next] == 0) // kind0=end of options
			break;
		/* kind1 = NOP and is a single byte, others have a length field */
		next += (smp->data.u.str.area[next] == 1) ? 1 : smp->data.u.str.area[next + 1];
		if (smp->data.u.str.area[curr] == opt && next <= len)
			return curr;
	}

	return 0;
}

/* returns the destination port field found in an input TCP header */
static int sample_conv_tcp_dst(const struct arg *arg_p, struct sample *smp, void *private)
{
	if (smp->data.u.str.data < 20)
		return 0;

	smp->data.u.sint = read_n16(smp->data.u.str.area + 2);
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the flags field found in an input TCP header */
static int sample_conv_tcp_flags(const struct arg *arg_p, struct sample *smp, void *private)
{
	if (smp->data.u.str.data < 20)
		return 0;

	smp->data.u.sint = (uchar)smp->data.u.str.area[13];
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the MSS value of an input TCP header, or 0 if absent. Returns
 * nothing if the header is incomplete.
 */
static int sample_conv_tcp_options_mss(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = tcp_fullhdr_find_opt(smp, 2 /* MSS */);

	if (!len)
		return 0;

	smp->data.u.sint = ofs ? read_n16(smp->data.u.str.area + ofs + 2) : 0;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns 1 if the SackPerm option is present in an input TCP header,
 * otherwise 0. Returns nothing if the header is incomplete.
 */
static int sample_conv_tcp_options_sack(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = tcp_fullhdr_find_opt(smp, 4 /* sackperm */);

	if (!len)
		return 0;

	smp->data.u.sint = !!ofs;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns 1 if the TimeStamp option is present in an input TCP header,
 * otherwise 0. Returns nothing if the header is incomplete.
 */
static int sample_conv_tcp_options_tsopt(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = tcp_fullhdr_find_opt(smp, 8 /* TS */);

	if (!len)
		return 0;

	smp->data.u.sint = !!ofs;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the TSval value in the TimeStamp option found in an input TCP
 * header, if found, otherwise 0. Returns nothing if the header is incomplete
 * (see also tsopt).
 */
static int sample_conv_tcp_options_tsval(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = tcp_fullhdr_find_opt(smp, 8 /* TS */);

	if (!len)
		return 0;

	smp->data.u.sint = ofs ? read_n32(smp->data.u.str.area + ofs + 2) : 0;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the window scaling shift count from an input TCP header, otherwise 0
 * if option not found (see also wsopt). Returns nothing if the header is
 * incomplete.
 */
static int sample_conv_tcp_options_wscale(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = tcp_fullhdr_find_opt(smp, 3 /* wscale */);

	if (!len)
		return 0;

	smp->data.u.sint = ofs ? (uchar)smp->data.u.str.area[ofs + 2] : 0;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns 1 if the WScale option is present in an input TCP header,
 * otherwise 0. Returns nothing if the header is incomplete.
 */
static int sample_conv_tcp_options_wsopt(const struct arg *arg_p, struct sample *smp, void *private)
{
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = tcp_fullhdr_find_opt(smp, 3 /* wscale */);

	if (!len)
		return 0;

	smp->data.u.sint = !!ofs;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns only the TCP options kinds of an input TCP header, as a binary
 * block of one byte per option.
 */
static int sample_conv_tcp_options_list(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	size_t len = tcp_fullhdr_length(smp);
	size_t ofs = 20;

	if (!len)
		return 0;

	while (ofs < len) {
		if (smp->data.u.str.area[ofs] == 0) // kind0=end of options
			break;
		trash->area[trash->data++] = smp->data.u.str.area[ofs];
		/* kind1 = NOP and is a single byte, others have a length field */
		if (smp->data.u.str.area[ofs] == 1)
			ofs++;
		else if (ofs + 1 <= len)
			ofs += smp->data.u.str.area[ofs + 1];
		else
			break;
	}

	/* returns a binary block of 1 byte per option */
	smp->data.u.str = *trash;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the sequence number field found in an input TCP header */
static int sample_conv_tcp_seq(const struct arg *arg_p, struct sample *smp, void *private)
{
	if (smp->data.u.str.data < 20)
		return 0;

	smp->data.u.sint = read_n32(smp->data.u.str.area + 4);
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the source port field found in an input TCP header */
static int sample_conv_tcp_src(const struct arg *arg_p, struct sample *smp, void *private)
{
	if (smp->data.u.str.data < 20)
		return 0;

	smp->data.u.sint = read_n16(smp->data.u.str.area);
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* returns the window field found in an input TCP header */
static int sample_conv_tcp_win(const struct arg *arg_p, struct sample *smp, void *private)
{
	if (smp->data.u.str.data < 20)
		return 0;

	smp->data.u.sint = read_n16(smp->data.u.str.area + 14);
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* Builds a binary fingerprint of the IP+TCP input contents that are supposed
 * to rely essentially on the client stack's settings. This can be used for
 * example to selectively block bad behaviors at one IP address without
 * blocking others. The resulting fingerprint is a binary block of 56 to 376
 * bytes long (56 being the fixed part and the rest depending on the provided
 * TCP extensions).
 */
static int sample_conv_ip_fp(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	char *ipsrc;
	uchar ipver;
	uchar iptos;
	uchar ipttl;
	uchar ipdf;
	uchar ipext;
	uchar tcpflags;
	uchar tcplen;
	uchar tcpws;
	ushort pktlen;
	ushort tcpwin;
	ushort tcpmss;
	size_t iplen;
	size_t ofs;
	int mode;

	/* check arg for mode > 0 */
	if (arg_p[0].type == ARGT_SINT)
		mode = arg_p[0].data.sint;
	else
		mode = 0;

	/* retrieve IP version */
	if (smp->data.u.str.data < 1)
		return 0;

	ipver = (uchar)smp->data.u.str.area[0] >> 4;
	if (ipver == 4) {
		/* check fields for IPv4 */

		// extension present if header length != 5 words.
		ipext = (smp->data.u.str.area[0] & 0xF) != 5;
		iplen = (smp->data.u.str.area[0] & 0xF) * 4;
		if (smp->data.u.str.data < iplen)
			return 0;

		iptos = smp->data.u.str.area[1];
		pktlen = read_n16(smp->data.u.str.area + 2);
		ipdf = !!(smp->data.u.str.area[6] & 0x40);
		ipttl = smp->data.u.str.area[8];
		ipsrc = smp->data.u.str.area + 12;
	}
	else if (ipver == 6) {
		/* check fields for IPv6 */
		if (smp->data.u.str.data < 40)
			return 0;

		pktlen = 40 + read_n16(smp->data.u.str.area + 4);
		// extension/next proto => ext present if !tcp && !udp
		ipext = smp->data.u.str.area[6];
		ipext = ipext != 6 && ipext != 17;

		iptos = read_n16(smp->data.u.str.area) >> 4;
		ipdf = 1; // no fragments by default in IPv6
		ipttl = smp->data.u.str.area[7];
		ipsrc = smp->data.u.str.area + 8;
	}
	else
		return 0;

	/* prepare trash to contain at least 7 bytes */
	trash->data = 7;

	/* store the TOS in the FP's first byte */
	trash->area[0] = iptos;

	if (mode & 1) // append TTL
		trash->area[trash->data++] = ipttl;

	/* keep only two bits for TTL: <=32, <=64, <=128, <=255 */
	ipttl = (ipttl > 64) ? ((ipttl > 128) ? 3 : 2) : ((ipttl > 32) ? 1 : 0);

	/* OK we've collected required IP fields, let's advance to TCP now */
	iplen = ip_header_length(smp);
	if (!iplen || iplen > pktlen)
		return 0;

	/* advance buffer by <len> */
	smp->data.u.str.area += iplen;
	smp->data.u.str.data -= iplen;
	pktlen -= iplen;

	/* now SMP points to the TCP header. It must be complete */
	tcplen = tcp_fullhdr_length(smp);
	if (!tcplen || tcplen > pktlen)
		return 0;

	pktlen -= tcplen; // remaining data length (e.g. TFO)
	tcpflags = smp->data.u.str.area[13];
	tcpwin   = read_n16(smp->data.u.str.area + 14);

	/* second byte of FP contains:
	 *   - bit 7..4: IP.v6(1), IP.DF(1), IP.TTL(2),
	 *   - bit 3..0: IP.ext(1), TCP.have_data(1), TCP.CWR(1), TCP.ECE(1)
	 */
	trash->area[1] =
		((ipver == 6)                    << 7) |
		(ipdf                            << 6) |
		(ipttl                           << 4) |
		(ipext                           << 3) |
		((pktlen > 0)                    << 2) | // data present (TFO)
		(tcpflags >> 6                   << 0);  // CWR, ECE

	tcpmss = tcpws = 0;
	ofs = 20;
	while (ofs < tcplen) {
		size_t next;

		if (smp->data.u.str.area[ofs] == 0) // kind0=end of options
			break;

		/* kind1 = NOP and is a single byte, others have a length field */
		if (smp->data.u.str.area[ofs] == 1)
			next = ofs + 1;
		else if (ofs + 1 <= tcplen)
			next = ofs + smp->data.u.str.area[ofs + 1];
		else
			break;

		if (next > tcplen)
			break;

		/* option is complete, take a copy of it */
		if (mode & 2) // mode & 2: append tcp.options_list
			trash->area[trash->data++] = smp->data.u.str.area[ofs];

		if (smp->data.u.str.area[ofs] == 2 /* MSS */) {
			tcpmss = read_n16(smp->data.u.str.area + ofs + 2);
		}
		else if (smp->data.u.str.area[ofs] == 3 /* WS */) {
			tcpws = (uchar)smp->data.u.str.area[ofs + 2];
			/* output from 1 to 15, thus 0=not found */
			tcpws = tcpws > 14 ? 15 : tcpws + 1;
		}
		ofs = next;
	}

	/* third byte contains hdrlen(4) and wscale(4) */
	trash->area[2] = (tcplen << 2) | tcpws;

	/* then tcpwin(16) then tcpmss(16) */
	write_n16(trash->area + 3, tcpwin);
	write_n16(trash->area + 5, tcpmss);

	/* mode 4: append source IP address */
	if (mode & 4) {
		iplen = (ipver == 4) ? 4 : 16;
		memcpy(trash->area + trash->data, ipsrc, iplen);
		trash->data += iplen;
	}

	/* option kinds if any are stored starting at offset 7 */
	smp->data.u.str = *trash;
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
	{ "ip.fp",              sample_conv_ip_fp,   ARG1(0,SINT),      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "ip.hdr",             sample_conv_ip_hdr,             0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "ip.proto",           sample_conv_ip_proto,           0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.src",             sample_conv_ip_src,             0,      NULL,      SMP_T_BIN,  SMP_T_ADDR },
	{ "ip.tos",             sample_conv_ip_tos,             0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.ttl",             sample_conv_ip_ttl,             0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "ip.ver",             sample_conv_ip_ver,             0,      NULL,      SMP_T_BIN,  SMP_T_SINT },

	{ "tcp.dst",            sample_conv_tcp_dst,            0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.flags",          sample_conv_tcp_flags,          0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options.mss",    sample_conv_tcp_options_mss,    0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options.sack",   sample_conv_tcp_options_sack,   0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options.tsopt",  sample_conv_tcp_options_tsopt,  0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options.tsval",  sample_conv_tcp_options_tsval,  0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options.wscale", sample_conv_tcp_options_wscale, 0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options.wsopt",  sample_conv_tcp_options_wsopt,  0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.options_list",   sample_conv_tcp_options_list,   0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "tcp.seq",            sample_conv_tcp_seq,            0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.src",            sample_conv_tcp_src,            0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "tcp.win",            sample_conv_tcp_win,            0,      NULL,      SMP_T_BIN,  SMP_T_SINT },

	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
