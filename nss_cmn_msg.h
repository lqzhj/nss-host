/*
 **************************************************************************
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * nss_cmn_msg
 *	Common Message Structure and APIs
 */

#ifndef __NSS_CMN_MSG_H
#define __NSS_CMN_MSG_H

/*
 * Common response structure
 */
enum nss_cmn_response {
	NSS_CMN_RESPONSE_ACK,		/* Message Acknowledge */
	NSS_CMN_RESPONSE_EVERSION,	/* Message Version Error */
	NSS_CMN_RESPONSE_EINTERFACE,	/* Message Interface Error */
	NSS_CMN_RESPONSE_ELENGTH,	/* Message Length Error */
	NSS_CMN_RESPONSE_EMSG,		/* Message Error */
	NSS_CMM_RESPONSE_NOTIFY,	/* Message Independant of Request */
	NSS_CMN_RESPONSE_LAST
};

/*
 * Common message structure
 */
struct nss_cmn_msg {
	uint16_t version;		/* Version id for main message format */
	uint16_t interface;		/* Primary Key for all messages */
	enum nss_cmn_response response;	/* Primary response */
	uint32_t type;			/* Decetralized request #, to be used to match response # */
	uint32_t error;			/* Decentralized specific error message, response == EMSG */
	uint32_t module;		/* Module where the callback resides */
	uint32_t cb;			/* Place for callback pointer */
	uint32_t app_data;		/* Place for app data */
	uint32_t len;			/* What is the length of the message excluding this header */
};

/*
 * Common per node stats structure
 */
struct nss_cmn_node_stats {
	uint32_t rx_packets;		/* Number of packets received */
	uint32_t rx_bytes;		/* Number of bytes received */
	uint32_t rx_dropped;		/* Number of receive drops due to queue full */
	uint32_t tx_packets;		/* Number of packets transmitted */
	uint32_t tx_bytes;		/* Number of bytes transmitted */
};
struct nss_ctx_instance;

extern void nss_cmn_msg_init(struct nss_cmn_msg *ncm, uint16_t if_num, uint32_t type,  uint32_t len,
	void *cb, void *app_data);

#endif /* __NSS_CMN_MSG_H */
