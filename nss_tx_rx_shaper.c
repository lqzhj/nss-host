/*
 **************************************************************************
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
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
 * nss_tx_rx_shaper.c
 *	NSS shaper APIs
 */

#include "nss_tx_rx_common.h"
#include <net/pkt_sched.h>

/*
 * nss_shaper_config_send()
 *	Issue a config message to the shaping subsystem of the NSS.
 */
nss_tx_status_t nss_shaper_config_send(void *ctx, struct nss_shaper_configure *config)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_tx_shaper_configure *ntsc;

	nss_info("%p:Shaper config: %p send:  if_num: %u i_shaper: %u, type: %d, owner: %p\n", nss_ctx,
		config, config->interface_num, config->i_shaper, config->type, config->owner);
	NSS_VERIFY_CTX_MAGIC(nss_ctx);

	/*
	 * Core should be ready
	 */
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Shaper config: %p core not ready", nss_ctx, config);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Allocate buffer for command
	 */
	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: Shaper config: %p alloc fail", nss_ctx, config);
		return NSS_TX_FAILURE;
	}

	/*
	 * Hold the module until we are done with the request
	 */
	if (!try_module_get(config->owner)) {
		nss_warning("%p: Shaper config: %p module shutting down: %p", nss_ctx, config, config->owner);
		return NSS_TX_FAILURE;
	}

	/*
	 * Copy the HLOS API structures command into the NSS metadata object command.
	 */
	nss_info("%p: config type: %d", nss_ctx, config->type);
	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_SHAPER_CONFIGURE;
	ntsc = &ntmo->sub.shaper_configure;

	ntsc->opaque1 = (uint32_t)config->cb;
	ntsc->opaque2 = (uint32_t)config->app_data;
	ntsc->opaque3 = (uint32_t)config->owner;
	ntsc->i_shaper = config->i_shaper;
	ntsc->interface_num = config->interface_num;

	switch(config->type) {
	case NSS_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER:
		nss_info("%p: Assign shaper num: %u", nss_ctx, config->mt.assign_shaper.shaper_num);
		ntsc->mt.assign_shaper.shaper_num = config->mt.assign_shaper.shaper_num;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER;
		break;
	case NSS_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE:
		nss_info("%p: Alloc shaper node type: %d, qos_tag: %x",
				nss_ctx, config->mt.alloc_shaper_node.node_type, config->mt.alloc_shaper_node.qos_tag);
		ntsc->mt.alloc_shaper_node.node_type = config->mt.alloc_shaper_node.node_type;
		ntsc->mt.alloc_shaper_node.qos_tag = config->mt.alloc_shaper_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE;
		break;
	case NSS_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE:
		nss_info("%p: Free shaper node qos_tag: %x",
				nss_ctx, config->mt.alloc_shaper_node.qos_tag);
		ntsc->mt.free_shaper_node.qos_tag = config->mt.free_shaper_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE;
		break;
	case NSS_SHAPER_CONFIG_TYPE_PRIO_ATTACH:
		nss_info("%p: Prio node: %x, attach: %x, priority: %u",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.prio_attach.child_qos_tag, config->mt.shaper_node_config.snc.prio_attach.priority);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.prio_attach.child_qos_tag = config->mt.shaper_node_config.snc.prio_attach.child_qos_tag;
		ntsc->mt.shaper_node_config.snc.prio_attach.priority = config->mt.shaper_node_config.snc.prio_attach.priority;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_PRIO_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_PRIO_DETACH:
		nss_info("%p: Prio node: %x, detach @ priority: %u",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.prio_detach.priority);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.prio_detach.priority = config->mt.shaper_node_config.snc.prio_detach.priority;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_PRIO_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM:
		nss_info("%p: Shaper node: %x", nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.codel_param.qlen_max = config->mt.shaper_node_config.snc.codel_param.qlen_max;
		ntsc->mt.shaper_node_config.snc.codel_param.cap.interval = config->mt.shaper_node_config.snc.codel_param.cap.interval;
		ntsc->mt.shaper_node_config.snc.codel_param.cap.target = config->mt.shaper_node_config.snc.codel_param.cap.target;
		ntsc->mt.shaper_node_config.snc.codel_param.cap.mtu = config->mt.shaper_node_config.snc.codel_param.cap.mtu;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_TBL_ATTACH:
		nss_info("%p: Tbl node: %x attach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.tbl_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.tbl_attach.child_qos_tag = config->mt.shaper_node_config.snc.tbl_attach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_TBL_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_TBL_DETACH:
		nss_info("%p: Tbl node: %x, detach",
				nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_TBL_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM:
		nss_info("%p: Tbl node: %x configure", nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.tbl_param.qlen_bytes = config->mt.shaper_node_config.snc.tbl_param.qlen_bytes;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.rate = config->mt.shaper_node_config.snc.tbl_param.lap_cir.rate;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.burst = config->mt.shaper_node_config.snc.tbl_param.lap_cir.burst;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.max_size = config->mt.shaper_node_config.snc.tbl_param.lap_cir.max_size;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit = config->mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.rate = config->mt.shaper_node_config.snc.tbl_param.lap_pir.rate;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.burst = config->mt.shaper_node_config.snc.tbl_param.lap_pir.burst;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.max_size = config->mt.shaper_node_config.snc.tbl_param.lap_pir.max_size;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit = config->mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_ATTACH:
		nss_info("%p: Bigfoot node: %x attach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.bf_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_attach.child_qos_tag = config->mt.shaper_node_config.snc.bf_attach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_DETACH:
		nss_info("%p: Bigfoot node: %x, detach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.bf_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_detach.child_qos_tag = config->mt.shaper_node_config.snc.bf_detach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH:
		nss_info("%p: Bigfoot group node: %x attach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag = config->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH:
		nss_info("%p: Bigfoot group node: %x, detach",
				nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM:
		nss_info("%p: Tbl node: %x configure", nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_group_param.qlen_bytes = config->mt.shaper_node_config.snc.bf_group_param.qlen_bytes;
		ntsc->mt.shaper_node_config.snc.bf_group_param.quantum = config->mt.shaper_node_config.snc.bf_group_param.quantum;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.rate = config->mt.shaper_node_config.snc.bf_group_param.lap.rate;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.burst = config->mt.shaper_node_config.snc.bf_group_param.lap.burst;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.max_size = config->mt.shaper_node_config.snc.bf_group_param.lap.max_size;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_SET_DEFAULT:
		nss_info("%p: Set default node qos_tag: %x",
				nss_ctx, config->mt.set_default_node.qos_tag);
		ntsc->mt.set_default_node.qos_tag = config->mt.set_default_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_SET_DEFAULT;
		break;
	case NSS_SHAPER_CONFIG_TYPE_SET_ROOT:
		nss_info("%p: Set root node qos_tag: %x",
				nss_ctx, config->mt.set_root_node.qos_tag);
		ntsc->mt.set_root_node.qos_tag = config->mt.set_root_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_SET_ROOT;
		break;
	case NSS_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER:
		nss_info("%p: UNassign shaper num: %u", nss_ctx, config->mt.unassign_shaper.shaper_num);
		ntsc->mt.unassign_shaper.shaper_num = config->mt.unassign_shaper.shaper_num;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER;
		break;
	case NSS_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM:
		nss_info("%p: fifo parameter set: %u, drop mode: %d", nss_ctx, config->mt.shaper_node_config.snc.fifo_param.limit,
				config->mt.shaper_node_config.snc.fifo_param.drop_mode);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.fifo_param.limit = config->mt.shaper_node_config.snc.fifo_param.limit;
		ntsc->mt.shaper_node_config.snc.fifo_param.drop_mode = (nss_tx_shaper_config_fifo_drop_mode_t)config->mt.shaper_node_config.snc.fifo_param.drop_mode;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET:
		nss_info("%p: Get basic statistics for: %u", nss_ctx, config->mt.shaper_node_basic_stats_get.qos_tag);
		ntsc->mt.shaper_node_basic_stats_get.qos_tag = config->mt.shaper_node_basic_stats_get.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET;
		break;
	default:
		/*
		 * Release module
		 */
		module_put(config->owner);
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unknown type: %d", nss_ctx, config->type);
		return NSS_TX_FAILURE;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		/*
		 * Release module
		 */
		module_put(config->owner);
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Shaper config: %p Unable to enqueue\n", nss_ctx, config);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_rx_metadata_shaper_response()
 *	Called to process a shaper response (to a shaper config command issued)
 */
static void nss_rx_metadata_shaper_response(struct nss_ctx_instance *nss_ctx, struct nss_rx_shaper_response *sr)
{
	struct nss_tx_shaper_configure *ntsc = &sr->request;
	nss_shaper_config_response_callback_t cb;
	void *cb_app_data;
	struct module *owner;
	struct nss_shaper_response response;

	/*
	 * Pass the response to the originator
	 */
	cb = (nss_shaper_config_response_callback_t)ntsc->opaque1;
	cb_app_data = (void *)ntsc->opaque2;
	owner = (struct module *)ntsc->opaque3;

	nss_info("%p: shaper response: %p, cb: %p, arg: %p, owner: %p, response type: %d, request type: %d\n",
			nss_ctx, sr, cb, cb_app_data, owner, sr->type, ntsc->type);
//	printk(KERN_INFO "%p: shaper response: %p, cb: %p, arg: %p, owner: %p, response type: %d, request type: %d\n",
//			nss_ctx, sr, cb, cb_app_data, owner, sr->type, ntsc->type);

	/*
	 * Create a response structure from the NSS metadata response
	 */
	switch(sr->type) {
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_ASSIGN_SUCCESS:
		nss_info("%p: assign shaper success num: %u", nss_ctx, sr->rt.shaper_assign_success.shaper_num);
		response.rt.shaper_assign_success.shaper_num = sr->rt.shaper_assign_success.shaper_num;
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_ASSIGN_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPERS:
		nss_info("%p: no shapers", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPERS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER:
		nss_info("%p: no shaper", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPER;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODE:
		nss_info("%p: no shaper node", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODE;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODES:
		nss_info("%p: no shaper nodes", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODES;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_OLD:
		nss_info("%p: old request", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_OLD;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_UNRECOGNISED:
		nss_info("%p: unrecognised command", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_UNRECOGNISED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_QUEUE_LIMIT_INVALID:
		nss_info("%p: fifo queue limit set fail", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_FIFO_QUEUE_LIMIT_INVALID;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_DROP_MODE_INVALID:
		nss_info("%p: fifo drop mode fail", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_FIFO_DROP_MODE_INVALID;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BAD_DEFAULT_CHOICE:
		nss_info("%p: bad default choice", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BAD_DEFAULT_CHOICE;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_DUPLICATE_QOS_TAG:
		nss_info("%p: Duplicate qos tag", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_DUPLICATE_QOS_TAG;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_RATE_AND_BURST_REQUIRED:
		nss_info("%p: Burst size and rate must be provided for CIR", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_CIR_RATE_AND_BURST_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_BURST_LESS_THAN_MTU:
		nss_info("%p: CIR burst size cannot be smaller than mtu", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_BURST_LESS_THAN_MTU;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_LESS_THAN_MTU:
		nss_info("%p: PIR burst size cannot be smaller than mtu", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_LESS_THAN_MTU;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_REQUIRED:
		nss_info("%p: PIR burst size required if peakrate is specifies", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_ALL_PARAMS_REQUIRED:
		nss_info("%p: Codel requires non-zero value for target, interval and limit", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_ALL_PARAMS_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_ALLOC_SUCCESS:
		nss_info("%p: node alloc success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_NODE_ALLOC_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_PRIO_ATTACH_SUCCESS:
		nss_info("%p: prio attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_PRIO_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_PRIO_DETACH_SUCCESS:
		nss_info("%p: prio detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_PRIO_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_CHANGE_PARAM_SUCCESS:
		nss_info("%p: codel configure success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_CODEL_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_ATTACH_SUCCESS:
		nss_info("%p: tbl attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_DETACH_SUCCESS:
		nss_info("%p: tbl detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CHANGE_PARAM_SUCCESS:
		nss_info("%p: tbl configure success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_ATTACH_SUCCESS:
		nss_info("%p: bf attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_DETACH_SUCCESS:
		nss_info("%p: bf detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_ATTACH_SUCCESS:
		nss_info("%p: bf group attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_GROUP_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_DETACH_SUCCESS:
		nss_info("%p: bf group detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_GROUP_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_CHANGE_PARAM_SUCCESS:
		nss_info("%p: bf group configure success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_GROUP_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_SET_ROOT_SUCCESS:
		nss_info("%p: shaper root set success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_SET_ROOT_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_SET_DEFAULT_SUCCESS:
		nss_info("%p: shaper default set success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_SET_DEFAULT_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_FREE_SUCCESS:
		nss_info("%p: node free success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_NODE_FREE_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_UNASSIGN_SUCCESS:
		nss_info("%p: unassign shaper success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_UNASSIGN_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_CHANGE_PARAM_SUCCESS:
		nss_info("%p: fifo limit set success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_FIFO_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_BASIC_STATS_GET_SUCCESS:
		nss_info("%p: basic stats success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_NODE_BASIC_STATS_GET_SUCCESS;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_packets = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_packets;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_packets_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_packets_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_packets = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_packets;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_packets_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_packets_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.queue_overrun = sr->rt.shaper_node_basic_stats_get_success.delta.queue_overrun;
		response.rt.shaper_node_basic_stats_get_success.qlen_bytes = sr->rt.shaper_node_basic_stats_get_success.qlen_bytes;
		response.rt.shaper_node_basic_stats_get_success.qlen_packets = sr->rt.shaper_node_basic_stats_get_success.qlen_packets;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dequeued = sr->rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dequeued;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dequeued = sr->rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dequeued;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dropped = sr->rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dropped;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dropped = sr->rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dropped;
		break;
	default:
		module_put(owner);
		nss_warning("%p: unknown response type: %d\n", nss_ctx, response.type);
		return;
	}

	/*
	 * Re-Create original request
	 */
	response.request.i_shaper = ntsc->i_shaper;
	response.request.interface_num = ntsc->interface_num;
	switch(ntsc->type) {
	case NSS_TX_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER:
		nss_info("%p: assign shaper num: %u", nss_ctx, ntsc->mt.assign_shaper.shaper_num);
		response.request.mt.assign_shaper.shaper_num = ntsc->mt.assign_shaper.shaper_num;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE:
		nss_info("%p: Alloc shaper node type: %d, qos_tag: %x",
				nss_ctx, ntsc->mt.alloc_shaper_node.node_type, ntsc->mt.alloc_shaper_node.qos_tag);
		response.request.mt.alloc_shaper_node.node_type = ntsc->mt.alloc_shaper_node.node_type;
		response.request.mt.alloc_shaper_node.qos_tag = ntsc->mt.alloc_shaper_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE:
		nss_info("%p: Free shaper node qos_tag: %x",
				nss_ctx, ntsc->mt.alloc_shaper_node.qos_tag);
		response.request.mt.free_shaper_node.qos_tag = ntsc->mt.free_shaper_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_PRIO_ATTACH:
		nss_info("%p: Prio node: %x, attach: %x, priority: %u",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.prio_attach.child_qos_tag, ntsc->mt.shaper_node_config.snc.prio_attach.priority);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.prio_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.prio_attach.child_qos_tag;
		response.request.mt.shaper_node_config.snc.prio_attach.priority = ntsc->mt.shaper_node_config.snc.prio_attach.priority;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_PRIO_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_PRIO_DETACH:
		nss_info("%p: Prio node: %x, detach @ priority: %u",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.prio_detach.priority);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.prio_detach.priority = ntsc->mt.shaper_node_config.snc.prio_detach.priority;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_PRIO_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM:
		nss_info("%p: Codel node: %x, configure", nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.codel_param.qlen_max = ntsc->mt.shaper_node_config.snc.codel_param.qlen_max;
		response.request.mt.shaper_node_config.snc.codel_param.cap.interval = ntsc->mt.shaper_node_config.snc.codel_param.cap.interval;
		response.request.mt.shaper_node_config.snc.codel_param.cap.target = ntsc->mt.shaper_node_config.snc.codel_param.cap.target;
		response.request.mt.shaper_node_config.snc.codel_param.cap.mtu = ntsc->mt.shaper_node_config.snc.codel_param.cap.mtu;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_TBL_ATTACH:
		nss_info("%p: Tbl node: %x, attach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.tbl_attach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.tbl_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.tbl_attach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_TBL_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_TBL_DETACH:
		nss_info("%p: Tbl node: %x, detach",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_TBL_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM:
		nss_info("%p: Tbl node: %x, configure", nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.tbl_param.qlen_bytes = ntsc->mt.shaper_node_config.snc.tbl_param.qlen_bytes;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.rate = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.rate;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.burst = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.burst;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.max_size = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.max_size;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.rate = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.rate;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.burst = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.burst;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.max_size = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.max_size;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_ATTACH:
		nss_info("%p: Bigfoot node: %x, attach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.bf_attach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.bf_attach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_DETACH:
		nss_info("%p: Bigfoot node: %x, detach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.bf_detach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_detach.child_qos_tag = ntsc->mt.shaper_node_config.snc.bf_detach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH:
		nss_info("%p: Bigfoot group node: %x, attach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_group_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH:
		nss_info("%p: Bigfoot group node: %x, detach",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM:
		nss_info("%p: Bigfoot group node: %x, configure", nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_group_param.qlen_bytes = ntsc->mt.shaper_node_config.snc.bf_group_param.qlen_bytes;
		response.request.mt.shaper_node_config.snc.bf_group_param.quantum = ntsc->mt.shaper_node_config.snc.bf_group_param.quantum;
		response.request.mt.shaper_node_config.snc.bf_group_param.lap.rate = ntsc->mt.shaper_node_config.snc.bf_group_param.lap.rate;
		response.request.mt.shaper_node_config.snc.bf_group_param.lap.burst = ntsc->mt.shaper_node_config.snc.bf_group_param.lap.burst;
		response.request.mt.shaper_node_config.snc.bf_group_param.lap.max_size = ntsc->mt.shaper_node_config.snc.bf_group_param.lap.max_size;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_SET_DEFAULT:
		nss_info("%p: Set default node qos_tag: %x",
				nss_ctx, ntsc->mt.set_default_node.qos_tag);
		response.request.mt.set_default_node.qos_tag = ntsc->mt.set_default_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_SET_DEFAULT;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_SET_ROOT:
		nss_info("%p: Set root node qos_tag: %x",
				nss_ctx, ntsc->mt.set_root_node.qos_tag);
		response.request.mt.set_root_node.qos_tag = ntsc->mt.set_root_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_SET_ROOT;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER:
		nss_info("%p: unassign shaper num: %u", nss_ctx, ntsc->mt.unassign_shaper.shaper_num);
		response.request.mt.unassign_shaper.shaper_num = ntsc->mt.unassign_shaper.shaper_num;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM:
		nss_info("%p: fifo param limit set: %u, drop_mode: %d", nss_ctx, ntsc->mt.shaper_node_config.snc.fifo_param.limit,
				ntsc->mt.shaper_node_config.snc.fifo_param.drop_mode);
		response.request.mt.shaper_node_config.snc.fifo_param.limit = ntsc->mt.shaper_node_config.snc.fifo_param.limit;
		response.request.mt.shaper_node_config.snc.fifo_param.drop_mode = (nss_shaper_config_fifo_drop_mode_t)ntsc->mt.shaper_node_config.snc.fifo_param.drop_mode;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET:
		nss_info("%p: basic stats get for: %u", nss_ctx, ntsc->mt.shaper_node_basic_stats_get.qos_tag);
		response.request.mt.shaper_node_basic_stats_get.qos_tag = ntsc->mt.shaper_node_basic_stats_get.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET;
		break;
	default:
		module_put(owner);
		nss_warning("%p: Unknown request type: %d", nss_ctx, ntsc->type);
		return;
	}

	/*
	 * Return the response
	 */
	cb(cb_app_data, &response);
	module_put(owner);
}

/*
 * nss_register_shaping()
 *	Register to obtain an NSS context for basic shaping operations
 */
void *nss_register_shaping(void)
{
	if (nss_top_main.shaping_handler_id == (uint8_t)-1) {
		nss_warning("%p: SHAPING IS NOT ENABLED", __func__);
		return NULL;
	}
	return (void *)&nss_top_main.nss[nss_top_main.shaping_handler_id];
}

/*
 * nss_unregister_shaping()
 *	Unregister an NSS shaping context
 */
void nss_unregister_shaping(void *nss_ctx)
{
}

/*
 * nss_register_shaper_bounce_interface()
 *	Register for performing shaper bounce operations for interface shaper
 */
void *nss_register_shaper_bounce_interface(uint32_t if_num, nss_shaper_bounced_callback_t cb, void *app_data, struct module *owner)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_shaper_bounce_registrant *reg;

	nss_info("Shaper bounce interface register: %u, cb: %p, app_data: %p, owner: %p",
			if_num, cb, app_data, owner);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	/*
 	 * Shaping enabled?
	 */
	if (nss_top_main.shaping_handler_id == (uint8_t)-1) {
		nss_warning("%p: SHAPING IS NOT ENABLED", __func__);
		return NULL;
	}

	/*
	 * Can we hold the module?
	 */
	if (!try_module_get(owner)) {
		nss_warning("%p: Unable to hold owner", __func__);
		return NULL;
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must not have existing registrant
	 */
	reg = &nss_top->bounce_interface_registrants[if_num];
	if (reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		module_put(owner);
		nss_warning("Already registered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Register
	 */
	reg->bounced_callback = cb;
	reg->app_data = app_data;
	reg->owner = owner;
	reg->registered = true;
	spin_unlock_bh(&nss_top->lock);

	return (void *)&nss_top->nss[nss_top->shaping_handler_id];
}

/*
 * nss_unregister_shaper_bounce_interface()
 *	Unregister for shaper bounce operations for interface shaper
 */
void nss_unregister_shaper_bounce_interface(uint32_t if_num)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_shaper_bounce_registrant *reg;
	struct module *owner;

	nss_info("Shaper bounce interface unregister: %u", if_num);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must have existing registrant
	 */
	reg = &nss_top->bounce_interface_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("Already unregistered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Unegister
	 */
	owner = reg->owner;
	reg->owner = NULL;
	reg->registered = false;
	spin_unlock_bh(&nss_top->lock);

	module_put(owner);
}

/*
 * nss_register_shaper_bounce_bridge()
 *	Register for performing shaper bounce operations for bridge shaper
 */
void *nss_register_shaper_bounce_bridge(uint32_t if_num, nss_shaper_bounced_callback_t cb, void *app_data, struct module *owner)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx;
	struct nss_shaper_bounce_registrant *reg;

	nss_info("Shaper bounce bridge register: %u, cb: %p, app_data: %p, owner: %p",
			if_num, cb, app_data, owner);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	/*
 	 * Shaping enabled?
	 */
	if (nss_top_main.shaping_handler_id == (uint8_t)-1) {
		nss_warning("%p: SHAPING IS NOT ENABLED", __func__);
		return NULL;
	}

	/*
	 * Can we hold the module?
	 */
	if (!try_module_get(owner)) {
		nss_warning("%p: Unable to hold owner", __func__);
		return NULL;
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must not have existing registrant
	 */
	reg = &nss_top->bounce_bridge_registrants[if_num];
	if (reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		module_put(owner);
		nss_warning("Already registered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Register
	 */
	reg->bounced_callback = cb;
	reg->app_data = app_data;
	reg->owner = owner;
	reg->registered = true;
	spin_unlock_bh(&nss_top->lock);

	nss_ctx = &nss_top->nss[nss_top->shaping_handler_id];
	return (void *)nss_ctx;
}

/*
 * nss_unregister_shaper_bounce_bridge()
 *	Unregister for shaper bounce operations for bridge shaper
 */
void nss_unregister_shaper_bounce_bridge(uint32_t if_num)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_shaper_bounce_registrant *reg;
	struct module *owner;

	nss_info("Shaper bounce bridge unregister: %u", if_num);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must have existing registrant
	 */
	reg = &nss_top->bounce_bridge_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("Already unregistered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Wait until any bounce callback that is active is finished
	 */
	while (reg->callback_active) {
		spin_unlock_bh(&nss_top->stats_lock);
		yield();
		spin_lock_bh(&nss_top->stats_lock);
	}

	/*
	 * Unegister
	 */
	owner = reg->owner;
	reg->owner = NULL;
	reg->registered = false;
	spin_unlock_bh(&nss_top->lock);

	module_put(owner);
}

/*
 * nss_shaper_bounce_interface_packet()
 *	Bounce a packet to the NSS for interface shaping.
 *
 * You must have registered for interface bounce shaping to call this.
 */
nss_tx_status_t nss_shaper_bounce_interface_packet(void *ctx, uint32_t if_num, struct sk_buff *skb)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_shaper_bounce_registrant *reg;
	int32_t status;

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}


	/*
	 * Must have existing registrant
	 */
	spin_lock_bh(&nss_top->lock);
	reg = &nss_top->bounce_interface_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("unregistered: %u", if_num);
		return NSS_TX_FAILURE;
	}
	spin_unlock_bh(&nss_top->lock);

	status = nss_core_send_buffer(nss_ctx, if_num, skb, 0, H2N_BUFFER_SHAPER_BOUNCE_INTERFACE, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		return NSS_TX_FAILURE;
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_shaper_bounce_bridge_packet()
 *	Bounce a packet to the NSS for bridge shaping.
 *
 * You must have registered for bridge bounce shaping to call this.
 */
nss_tx_status_t nss_shaper_bounce_bridge_packet(void *ctx, uint32_t if_num, struct sk_buff *skb)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_shaper_bounce_registrant *reg;
	int32_t status;

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Must have existing registrant
	 */
	spin_lock_bh(&nss_top->lock);
	reg = &nss_top->bounce_bridge_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("unregistered: %u", if_num);
		return NSS_TX_FAILURE;
	}
	spin_unlock_bh(&nss_top->lock);

	nss_info("%s: Bridge bounce skb: %p, if_num: %u, ctx: %p", __func__, skb, if_num, nss_ctx);
	status = nss_core_send_buffer(nss_ctx, if_num, skb, NSS_IF_CMD_QUEUE, H2N_BUFFER_SHAPER_BOUNCE_BRIDGE, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		nss_info("%s: Bridge bounce core send rejected", __func__);
		return NSS_TX_FAILURE;
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

EXPORT_SYMBOL(nss_shaper_bounce_bridge_packet);
EXPORT_SYMBOL(nss_shaper_bounce_interface_packet);
EXPORT_SYMBOL(nss_unregister_shaper_bounce_interface);
EXPORT_SYMBOL(nss_register_shaper_bounce_interface);
EXPORT_SYMBOL(nss_unregister_shaper_bounce_bridge);
EXPORT_SYMBOL(nss_register_shaper_bounce_bridge);
EXPORT_SYMBOL(nss_register_shaping);
EXPORT_SYMBOL(nss_unregister_shaping);
EXPORT_SYMBOL(nss_shaper_config_send);