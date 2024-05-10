/*
 * include/haproxy/qpack-t.h
 * This file contains types for QPACK
 *
 * Copyright 2021 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QPACK_T_H
#define _HAPROXY_QPACK_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

/* Encoder */
/* Instruction bitmask */
#define QPACK_ENC_INST_BITMASK  0xf0
/* Instructions */
#define QPACK_ENC_INST_DUP      0x00 // Duplicate
#define QPACK_ENC_INST_SDTC_BIT 0x20 // Set Dynamic Table Capacity
#define QPACK_ENC_INST_IWLN_BIT 0x40 // Insert With Literal Name
#define QPACK_ENC_INST_IWNR_BIT 0x80 // Insert With Name Reference

/* Decoder */
/* Instructions bitmask */
#define QPACK_DEC_INST_BITMASK  0xf0
/* Instructions */
#define QPACK_DEC_INST_ICINC    0x00 // Insert Count Increment
#define QPACK_DEC_INST_SCCL     0x40 // Stream Cancellation
#define QPACK_DEC_INST_SACK     0x80 // Section Acknowledgment

/* RFC 9204 6. Error Handling */
enum qpack_err {
	QPACK_ERR_DECOMPRESSION_FAILED = 0x200,
	QPACK_ERR_ENCODER_STREAM_ERROR = 0x201,
	QPACK_ERR_DECODER_STREAM_ERROR = 0x202,
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QPACK_T_H */
