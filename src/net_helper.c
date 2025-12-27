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

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "eth.data",           sample_conv_eth_data,           0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.dst",            sample_conv_eth_dst,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.hdr",            sample_conv_eth_hdr,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.proto",          sample_conv_eth_proto,          0,      NULL,      SMP_T_BIN,  SMP_T_SINT },
	{ "eth.src",            sample_conv_eth_src,            0,      NULL,      SMP_T_BIN,  SMP_T_BIN  },
	{ "eth.vlan",           sample_conv_eth_vlan,           0,      NULL,      SMP_T_BIN,  SMP_T_SINT },

	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
