/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */
#ifndef __NSS_IPSEC_MGR_H
#define __NSS_IPSEC_MGR_H

#define NSS_IPSEC_ENCAP_INTERFACE NSS_IPSEC_ENCAP_IF_NUMBER
#define NSS_IPSEC_DECAP_INTERFACE NSS_IPSEC_DECAP_IF_NUMBER

#define NSS_IPSEC_DBG_DUMP_LIMIT 64
#define NSS_IPSEC_IPHDR_SZ sizeof(struct nss_ipsec_ipv4_hdr)
#define NSS_IPSEC_ESPHDR_SZ sizeof(struct nss_ipsec_esp_hdr)

/**
 * @brief IPsec tbl types
 */
enum nss_ipsec_tbl_type {
	NSS_IPSEC_TBL_TYPE_NONE = 0,
	NSS_IPSEC_TBL_TYPE_ENCAP = 1,
	NSS_IPSEC_TBL_TYPE_DECAP = 2,
	NSS_IPSEC_TBL_TYPE_MAX
};

/**
 * @brief IPsec trable entry state
 */
enum nss_ipsec_tbl_entry {
	NSS_IPSEC_TBL_ENTRY_DELETED = 0,
	NSS_IPSEC_TBL_ENTRY_PASSIVE = 1,
	NSS_IPSEC_TBL_ENTRY_ACTIVE = 2,
};

/**
 * @brief IPsec rule entry
 */
struct nss_ipsec_rule_entry {
	struct nss_ipsec_rule_sel sel;
	struct nss_ipsec_rule_data data;

	uint8_t aging;
	uint8_t res[3];
};

#endif /* __NSS_IPSEC_MGR_H */
