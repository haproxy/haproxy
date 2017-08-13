/*
 * include/proto/dns.h
 * This file provides functions related to DNS protocol
 *
 * Copyright (C) 2014 Baptiste Assmann <bedis9@gmail.com>
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

#ifndef _PROTO_DNS_H
#define _PROTO_DNS_H

#include <types/dns.h>
#include <types/proto_udp.h>

char *dns_str_to_dn_label(const char *string, char *dn, int dn_len);
int dns_str_to_dn_label_len(const char *string);
void dns_dn_label_to_str(char *dn, char *str, int dn_len);
int dns_hostname_validation(const char *string, char **err);
int dns_build_query(int query_id, int query_type, unsigned int accepted_payload_size, char *hostname_dn, int hostname_dn_len, char *buf, int bufsize);
struct task *dns_process_resolve(struct task *t);
int dns_init_resolvers(int close_socket);
uint16_t dns_rnd16(void);
int dns_validate_dns_response(unsigned char *resp, unsigned char *bufend, struct dns_resolution *resolution);
int dns_get_ip_from_response(struct dns_response_packet *dns_p,
                             struct dns_options *dns_opts, void *currentip,
                             short currentip_sin_family,
                             void **newip, short *newip_sin_family,
                             void *owner);
void dns_resolve_send(struct dgram_conn *dgram);
void dns_resolve_recv(struct dgram_conn *dgram);
int dns_send_query(struct dns_resolution *resolution);
void dns_print_current_resolutions(struct dns_resolvers *resolvers);
void dns_update_resolvers_timeout(struct dns_resolvers *resolvers);
void dns_reset_resolution(struct dns_resolution *resolution);
void dns_resolution_free(struct dns_resolvers *resolvers, struct dns_resolution *resolution);
void dns_rm_requester_from_resolution(struct dns_requester *requester, struct dns_resolution *resolution);
int dns_check_resolution_queue(struct dns_resolvers *resolvers);
unsigned short dns_response_get_query_id(unsigned char *resp);
struct dns_resolution *dns_alloc_resolution(void);
void dns_free_resolution(struct dns_resolution *resolution);
struct chunk *dns_cache_key(int query_type, char *hostname_dn, int hostname_dn_len, struct chunk *buf);
struct lru64 *dns_cache_lookup(int query_type, char *hostname_dn, int hostname_dn_len, int valid_period, void *cache_domain);
int dns_link_resolution(void *requester, int requester_type, struct dns_resolution *resolution);
struct dns_resolution *dns_resolution_list_get(struct dns_resolvers *resolvers, char *hostname_dn, int query_type);
int dns_trigger_resolution(struct dns_resolution *resolution);
int dns_alloc_resolution_pool(struct dns_resolvers *resolvers);

void dump_dns_config(void);

/*
 * erases all information of a dns_requester structure
 */
#define		dns_clear_requester(requester)	memset(requester, '\0', sizeof(*requester));

#endif // _PROTO_DNS_H
