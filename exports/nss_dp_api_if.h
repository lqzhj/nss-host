/*
 **************************************************************************
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
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
 * nss_dp_api_if.h
 *	nss-dp exported structure/apis.
 */

#ifndef __DP_API_IF_H
#define __DP_API_IF_H

/*
 * NSS DP status
 */
#define NSS_DP_SUCCESS	0
#define NSS_DP_FAILURE	-1

/*
 * NSS data plane ops, default would be slowpath and can be overridden by
 * nss-drv
 */
struct nss_dp_data_plane_ops {
	int (*init)(void *ctx);
	int (*open)(void *ctx, uint32_t tx_desc_ring, uint32_t rx_desc_ring,
							uint32_t mode);
	int (*close)(void *ctx);
	int (*link_state)(void *ctx, uint32_t link_state);
	int (*mac_addr)(void *ctx, uint8_t *addr);
	int (*change_mtu)(void *ctx, uint32_t mtu);
	int (*xmit)(void *ctx, struct sk_buff *os_buf);
	void (*set_features)(void *ctx);
	int (*pause_on_off)(void *ctx, uint32_t pause_on);
};

/*
 * nss_dp_receive()
 */
void nss_dp_receive(struct net_device *netdev, struct sk_buff *skb,
						struct napi_struct *napi);

/*
 * nss_dp_is_in_open_state()
 */
bool nss_dp_is_in_open_state(struct net_device *netdev);

/*
 * nss_dp_override_data_palne()
 */
int nss_dp_override_data_plane(struct net_device *netdev,
			       struct nss_dp_data_plane_ops *dp_ops, void *ctx);

/*
 * nss_dp_start_data_plane()
 */
void nss_dp_start_data_plane(struct net_device *netdev, void *ctx);

/*
 * nss_dp_restore_data_plane()
 */
void nss_dp_restore_data_plane(struct net_device *netdev);

/*
 * nss_dp_get_netdev_by_macid()
 */
struct net_device *nss_dp_get_netdev_by_macid(int macid);

#endif	/* __DP_API_IF_H */
