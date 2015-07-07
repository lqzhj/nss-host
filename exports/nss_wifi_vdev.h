/*
 **************************************************************************
 * Copyright (c) 2015, The Linux Foundation. All rights reserved.
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
  * nss_wifivdev.h
  * 	NSS TO HLOS interface definitions.
  */
#ifndef __NSS_WIFI_VDEV_H
#define __NSS_WIFI_VDEV_H

#define NSS_WIFI_HTT_TRANSFER_HDRSIZE_WORD 6
#define NSS_WIFI_VDEV_PER_PACKET_METADATA_OFFSET 4

/**
 * WIFI VDEV messages
 */
enum nss_wifi_vdev_msg_types {
	NSS_WIFI_VDEV_INTERFACE_CONFIGURE_MSG,
	NSS_WIFI_VDEV_INTERFACE_UP_MSG,
	NSS_WIFI_VDEV_INTERFACE_DOWN_MSG,
	NSS_WIFI_VDEV_INTERFACE_CMD_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_LIST_CREATE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_LIST_DELETE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_MEMBER_ADD_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_MEMBER_REMOVE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_GRP_MEMBER_UPDATE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DENY_MEMBER_ADD_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DENY_LIST_DELETE_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DENY_LIST_DUMP_MSG,
	NSS_WIFI_VDEV_SNOOPLIST_DUMP_MSG,
	NSS_WIFI_VDEV_MAX_MSG
};

/**
 * wifi vdev error types
 */
enum {
	NSS_WIFI_VDEV_ENONE,				/**< no error */
	NSS_WIFI_VDEV_EUNKNOWN_MSG,			/**< unknown message */
	NSS_WIFI_VDEV_EINV_VID_CONFIG,			/**< error in vid configuration information passed */
	NSS_WIFI_VDEV_EINV_EPID_CONFIG,			/**< error in epid configuration information passed */
	NSS_WIFI_VDEV_EINV_DL_CONFIG,			/**< error in download length configuration information passed */
	NSS_WIFI_VDEV_EINV_CMD,				/**< unknown command */
	NSS_WIFI_VDEV_EINV_ENCAP,			/**< invalid encap mode for vap */
	NSS_WIFI_VDEV_EINV_DECAP,			/**< invalid decap mode for vap */
	NSS_WIFI_VDEV_EINV_RX_NXTN,			/**< invalid next hop(node) in rx path */
	NSS_WIFI_VDEV_EINV_VID_INDEX,			/**< error in vid index */
	NSS_WIFI_VDEV_EINV_MC_CFG,			/**< error in multicast config */
	NSS_WIFI_VDEV_SNOOPTABLE_FULL,			/**< snooptable full error */
	NSS_WIFI_VDEV_SNOOPTABLE_ENOMEM,		/**< error in allocating memory for snooptable */
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_LIST_UNAVAILABLE,	/**< grp_list is unavailable in snooplist */
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_MEMBER_UNAVAILABLE,/**< grp_member is unavailable in grp_list inside snooplist */
	NSS_WIFI_VDEV_SNOOPTABLE_PEER_UNAVAILABLE,	/**< peer is unavailable */
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_LIST_ENOMEM,	/**< error in allocating memory for grplist in snooptable */
	NSS_WIFI_VDEV_SNOOPTABLE_GRP_LIST_EXIST,	/**< grp_list already exists in snooplist */
	NSS_WIFI_VDEV_ME_ENOMEM,			/**< error in allocating memory for multicast enhancement instance */
	NSS_WIFI_VDEV_EINV_NAWDS_CFG			/**< error in nawds config */
};

/**
 * Extended data plane pkt types sent from NSS to host.
 */
enum nss_wifi_vdev_ext_data_pkt_type {
        NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_NONE = 0,
        NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_IGMP = 1,		/**< igmp packets */
        NSS_WIFI_VDEV_EXT_DATA_PKT_TYPE_MAX
};

/**
 * wifi vdev commands
 */
enum nss_wifi_vdev_cmd {
	NSS_WIFI_VDEV_DROP_UNENC_CMD,		/**< command to set/reset encryption on vap */
	NSS_WIFI_VDEV_ENCAP_TYPE_CMD,		/**< command to configure encap mode of vap */
	NSS_WIFI_VDEV_DECAP_TYPE_CMD,		/**< command to configure decap mode of vap */
	NSS_WIFI_VDEV_ENABLE_ME_CMD,		/**< command to enable multicast enhancement */
	NSS_WIFI_VDEV_NAWDS_MODE_CMD,		/**< command to configure NAWDS on vap */
};

/**
 * wifi vdev config message
 */
struct nss_wifi_vdev_config_msg {
	uint8_t mac_addr[ETH_ALEN];	/**< MAC address */
	uint8_t reserved[2];		/**< reserved bytes */
	uint32_t vdev_id;		/**< vap id */
	uint32_t epid;			/**< CE endpoint id */
	uint32_t downloadlen;		/**< Header download length */
	uint32_t hdrcachelen;		/**< Header cache length */
	uint32_t hdrcache[NSS_WIFI_HTT_TRANSFER_HDRSIZE_WORD];
					/**< Header cache */
};

/**
 * wifi vdev enable message
 */
struct nss_wifi_vdev_enable_msg {
	uint8_t mac_addr[ETH_ALEN];	/**< MAC address */
	uint8_t reserved[2];		/**< reserved bytes */
};

/**
 * wifi vdev disable message
 */
struct nss_wifi_vdev_disable_msg {
	uint32_t reserved;		/**< place holder */
};

/** wifi vdev command message
 *
 */
struct nss_wifi_vdev_cmd_msg {
	uint32_t cmd;				/**< command type */
	uint32_t value;				/**< command value */
};

/**
 * wifi snooplist create grp_list
 */
struct nss_wifi_vdev_snooplist_grp_list_create_msg {
	uint32_t grp_ipaddr;			/**< multicast group ip address */
	uint8_t grp_addr[ETH_ALEN];		/**< multicast group mac address */
};

/**
 * wifi snooplist delete grp_list
 */
struct nss_wifi_vdev_snooplist_grp_list_delete_msg {
	uint32_t grp_ipaddr;			/**< multicast group ip address */
	uint8_t grp_addr[ETH_ALEN];		/**< multicast group mac address */
};

/**
 * wifi snooplist add grp_member
 */
struct nss_wifi_vdev_snooplist_grp_member_add_msg {
	uint32_t src_ip_addr;			/**< source ip address */
	uint32_t grpaddr;			/**< multicast group ip address */
	uint32_t peer_id;			/**< peer_id */
	uint8_t grp_addr[ETH_ALEN];		/**< multicast group mac address */
	uint8_t grp_member_addr[ETH_ALEN];	/**< multicast group member mac address */
	uint8_t mode;				/**< mode */
};

/**
 * wifi snooplist remove grp_member
 */
struct nss_wifi_vdev_snooplist_grp_member_remove_msg {
	uint32_t grp_ipaddr;			/**< multicast group ip address */
	uint8_t grp_addr[ETH_ALEN];		/**< multicast group mac address */
	uint8_t grp_member_addr[ETH_ALEN];	/**< multicast group member mac address */
};

/**
 * Wifi snooplist update grp_member.
 */
struct nss_wifi_vdev_snooplist_grp_member_update_msg {
	uint32_t src_ip_addr;			/**< source ip address */
	uint32_t grpaddr;			/**< multicast group ip address */
	uint8_t grp_addr[ETH_ALEN];		/**< multicast group mac address */
	uint8_t grp_member_addr[ETH_ALEN];	/**< multicast group member mac address */
	uint8_t mode;				/**< mode */
};

/**
 * Wifi snooplist add member to deny list.
 */
struct nss_wifi_vdev_snooplist_deny_member_add_msg {
	uint32_t grpaddr;			/**< multicast group ip address */
};

/**
 * Wifi per packet metadata for IGMP packets.
 */
struct nss_wifi_vdev_igmp_per_packet_metadata {
	uint32_t tid;				/**< tid value */
	uint32_t tsf32;				/**< tsf value */
	uint8_t peer_mac_addr[ETH_ALEN];	/**< peer mac address */
	uint8_t reserved[2];			/**< reserved */
};

/**
 * wifi per packet metadata content
 */
struct nss_wifi_vdev_per_packet_metadata {
	uint32_t pkt_type;
	union {
		struct nss_wifi_vdev_igmp_per_packet_metadata igmp_metadata;
	} metadata;
};

/**
 * wifi vdev specific messages
 */
struct nss_wifi_vdev_msg {
	struct nss_cmn_msg cm;          /* Message Header */
	union {
		struct nss_wifi_vdev_config_msg vdev_config;
		struct nss_wifi_vdev_enable_msg vdev_enable;
		struct nss_wifi_vdev_disable_msg vdev_disable;
		struct nss_wifi_vdev_cmd_msg vdev_cmd;
		struct nss_wifi_vdev_snooplist_grp_list_create_msg vdev_grp_list_create;
		struct nss_wifi_vdev_snooplist_grp_list_delete_msg vdev_grp_list_delete;
		struct nss_wifi_vdev_snooplist_grp_member_add_msg vdev_grp_member_add;
		struct nss_wifi_vdev_snooplist_grp_member_remove_msg vdev_grp_member_remove;
		struct nss_wifi_vdev_snooplist_grp_member_update_msg vdev_grp_member_update;
		struct nss_wifi_vdev_snooplist_deny_member_add_msg vdev_deny_member_add;
	} msg;
};

/**
 * @brief Send WIFI message to NSS
 *
 * @param nss_ctx NSS core context
 * @param msg  NSS wifi message
 *
 * @return status
 */
nss_tx_status_t nss_wifi_vdev_tx_msg(struct nss_ctx_instance *nss_ctx, struct nss_wifi_vdev_msg *msg);

/**
 * @brief Send WIFI data packet to NSS
 *
 * @param nss_ctx NSS core context
 * @param os_buf data buffer
 * @param if_num NSS interface number
 *
 * @return status
 */
nss_tx_status_t nss_wifi_vdev_tx_buf(struct nss_ctx_instance *nss_ctx, struct sk_buff *os_buf, uint32_t if_num);

/**
 * @brief Callback to receive wifi vdev messages
 *
 * @param app_data Application context of the message
 * @param msg Message data
 *
 * @return void
 */
typedef void (*nss_wifi_vdev_msg_callback_t)(void *app_data, struct nss_cmn_msg *msg);

/**
 * @brief Callback to receive wifi vdev data
 *
 * @param app_data Application context of the message
 * @param os_buf Pointer to data buffer
 *
 * @return void
 */
typedef void (*nss_wifi_vdev_callback_t)(struct net_device *netdev, struct sk_buff *skb, struct napi_struct *napi);

/**
 * @brief Callback to receive extended data plane wifi vdev data
 *
 * @param app_data Application context of the message
 * @param os_buf  Pointer to data buffer
 *
 * @return void
 */
typedef void (*nss_wifi_vdev_ext_data_callback_t)(struct net_device *netdev, struct sk_buff *skb, struct napi_struct *napi);

/**
 * @brief nss_wifi messages init function
 *
 * @return void
 */
void nss_wifi_vdev_msg_init(struct nss_wifi_vdev_msg *nim, uint16_t if_num, uint32_t type, uint32_t len,
				nss_wifi_vdev_msg_callback_t *cb, void *app_data);


/**
 * @brief Register wifi Vdev with NSS
 *
 * @param if_num NSS interface number
 * @param wifi_data_callback Callback for wifi vdev data
 * @param wifi_event_callback Callback for wifi vdev messages
 * @param netdev netdevice associated with the wifi vdev
 *
 * @return status
 */
uint32_t nss_register_wifi_vdev_if(struct nss_ctx_instance *nss_ctx, int32_t if_num, nss_wifi_vdev_callback_t wifi_data_callback,
			nss_wifi_vdev_ext_data_callback_t vdev_ext_data_callback, nss_wifi_vdev_msg_callback_t wifi_event_callback,
			struct net_device *netdev, uint32_t features);

/**
 * @brief Unregister wifi vdev interface with NSS
 *
 * @param if_num NSS interface number
 *
 * @return void
 */
void nss_unregister_wifi_vdev_if(uint32_t if_num);
#endif /* __NSS_WIFI_VDEV_H */
