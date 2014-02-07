/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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
 * Note: This file will be moved into the nss-qdisc directory once the driver
 * is re-organized.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/if_bridge.h>
#include <linux/list.h>
#include <nss_api_if.h>
#include <linux/version.h>
#include <br_private.h>

/*
 * NSS QDisc debug macros
 */
#if (NSSQDISC_DEBUG_LEVEL < 1)
#define nssqdisc_assert(fmt, args...)
#else
#define nssqdisc_assert(c) if (!(c)) { BUG_ON(!(c)); }
#endif

#if (NSSQDISC_DEBUG_LEVEL < 2)
#define nssqdisc_error(fmt, args...)
#else
#define nssqdisc_error(fmt, args...) printk(KERN_ERR "%d:ERROR:"fmt, __LINE__, ##args)
#endif

#if (NSSQDISC_DEBUG_LEVEL < 3)
#define nssqdisc_warning(fmt, args...)
#else
#define nssqdisc_warning(fmt, args...) printk(KERN_WARNING "%d:WARN:"fmt, __LINE__, ##args)
#endif

#if (NSSQDISC_DEBUG_LEVEL < 4)
#define nssqdisc_info(fmt, args...)
#else
#define nssqdisc_info(fmt, args...) printk(KERN_INFO "%d:INFO:"fmt, __LINE__, ##args)
#endif

#if (NSSQDISC_DEBUG_LEVEL < 5)
#define nssqdisc_trace(fmt, args...)
#else
#define nssqdisc_trace(fmt, args...) printk(KERN_DEBUG "%d:TRACE:"fmt, __LINE__, ##args)
#endif

/*
 * State values
 */
#define NSSQDISC_STATE_IDLE 0
#define NSSQDISC_STATE_READY 1
#define NSSQDISC_STATE_BUSY 2

#define NSSQDISC_STATE_INIT_FAILED -1
#define NSSQDISC_STATE_ASSIGN_SHAPER_SEND_FAIL -2
#define NSSQDISC_STATE_SHAPER_ASSIGN_FAILED -3
#define NSSQDISC_STATE_NODE_ALLOC_SEND_FAIL -4
#define NSSQDISC_STATE_NODE_ALLOC_FAIL -5
#define NSSQDISC_STATE_ROOT_SET_SEND_FAIL -6
#define NSSQDISC_STATE_ROOT_SET_FAIL -7
#define NSSQDISC_STATE_DEFAULT_SET_SEND_FAIL -8
#define NSSQDISC_STATE_DEFAULT_SET_FAIL -9
#define NSSQDISC_STATE_CHILD_ALLOC_SEND_FAIL -10
#define NSSQDISC_STATE_NODE_ALLOC_FAIL_CHILD -11
#define NSSQDISC_STATE_FAILED_RESPONSE -12

#define NSSQDISC_BRIDGE_PORT_MAX 100

void *nssqdisc_ctx;				/* Shaping context for nssqdisc */

struct nssqdisc_qdisc {
	struct Qdisc *qdisc;			/* Handy pointer back to containing qdisc */
	void *nss_shaping_ctx;			/* NSS context for general operations */
	int32_t nss_interface_number;		/* NSS Interface number we are shaping on */
	nss_shaper_node_type_t type;		/* Type of shaper node */
	bool is_root;				/* True if root qdisc on a net device */
	bool is_bridge;				/* True when qdisc is a bridge */
	bool is_virtual;			/* True when this is a non-bridge qdisc BUT
						 * the device is represented as a virtual in
						 * the NSS e.g. perhaps operating on a wifi interface.
						 */
	bool destroy_virtual_interface;		/* Set if the interface is first registered in NSS by
						 * us. This means it needs to be un-regisreted when the
						 * module goes down.
						 */
	volatile atomic_t state;		/* < 0: Signal that qdisc has 'failed'. 0
						 * indicates 'pending' setup.  > 0 is READY.
						 * NOTE: volatile AND atomic - this is polled
						 * AND is used for syncronisation.
						 */
	uint32_t shaper_id;			/* Used when is_root. Child qdiscs use this
						 * information to know what shaper under
						 * which to create shaper nodes
						 */
	uint32_t qos_tag;			/* QoS tag of this node */
	volatile int32_t pending_final_state;	/* Used to let the callback cycle know what
						 * state to set the qdisc in on successful
						 * completion.
						 */
	void *virtual_interface_context;	/* Context provided by the NSS driver for
						 * new interfaces that are registered.
						 */
	void *bounce_context;			/* Context for bounce registration. Bounce
						 * enables packets to be sent to NSS for
						 * shaping purposes, and is returned to
						 * Linux for transmit.
						 */
	void (*stats_update_callback)(void *, struct nss_shaper_response *);
						/* Stats update callback function for qdisc specific
						 * stats update
						 */
	struct timer_list stats_get_timer;	/* Timer used to poll for stats */
	atomic_t pending_stat_requests;		/* Number of pending stats responses */
	struct nss_shaper_response_shaper_node_basic_stats_get_success basic_stats_latest;
						/* Latest stats obtained */
};

/*
 * nssqdisc bridge update structure
 */
struct nssqdisc_bridge_update {
	int port_list[NSSQDISC_BRIDGE_PORT_MAX];
	int port_list_count;
	int unassign_count;
};

/*
 * nssqdisc bridge task types
 */
enum nssqdisc_bshaper_tasks {
	NSSQDISC_ASSIGN_BSHAPER,
	NSSQDISC_UNASSIGN_BSHAPER,
};

/*
 * nssqdisc_get_br_port()
 * 	Returns the bridge port structure of the bridge to which the device is attached to.
 */
static inline struct net_bridge_port *nssqdisc_get_br_port(const struct net_device *dev)
{
        struct net_bridge_port *br_port;

        if (!dev)
                return NULL;

        rcu_read_lock();
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0))
        br_port = br_port_get_rcu(dev);
#else
	br_port = rcu_dereference(dev->br_port);
#endif
        rcu_read_unlock();

        return br_port;
}

/*
 * nssqdisc_attach_bshaper_callback()
 *	Call back funtion for bridge shaper attach to an interface.
 */
static void nssqdisc_attach_bshaper_callback(void *app_data, struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	if (response->type < 0) {
		nssqdisc_info("%s: B-shaper attach FAILED - response: %d\n", __func__, response->type);
		atomic_set(&nq->state, NSSQDISC_STATE_FAILED_RESPONSE);
		return;
	}

	nssqdisc_info("%s: B-shaper attach SUCCESS - response %d\n", __func__, response->type);
	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_attach_bridge()
 *	Attaches a given bridge shaper to a given interface.
 */
static int nssqdisc_attach_bshaper(struct Qdisc *sch, uint32_t if_num)
{
	struct nss_shaper_configure shaper_assign;
	struct nssqdisc_qdisc *nq = (struct nssqdisc_qdisc *)qdisc_priv(sch);
	int32_t state, rc;

	nssqdisc_info("%s: Attaching B-shaper %u to interface %u\n", __func__,
			nq->shaper_id, if_num);

	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: qdisc %p (type %d) is not ready: State - %d\n",
				__func__, sch, nq->type, state);
		BUG();
	}

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	shaper_assign.interface_num = if_num;
	shaper_assign.i_shaper = false;
	shaper_assign.cb = nssqdisc_attach_bshaper_callback;
	shaper_assign.app_data = sch;
	shaper_assign.owner = THIS_MODULE;
	shaper_assign.type = NSS_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER;
	shaper_assign.mt.unassign_shaper.shaper_num = nq->shaper_id;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_assign);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_warning("%s: Failed to send bshaper (id: %u) attach for "
				"interface(if_num: %u)\n", __func__, nq->shaper_id, if_num);
		return -1;
	}

	while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
		yield();
	}

	if (state == NSSQDISC_STATE_FAILED_RESPONSE) {
		nssqdisc_error("%s: Failed to attach B-shaper %u to interface %u\n",
				__func__, nq->shaper_id, if_num);
		return -1;
	}

	nssqdisc_info("%s: Attach of B-shaper %u to interface %u is complete\n",
			__func__, nq->shaper_id, if_num);
	return 0;
}

/*
 * nssqdisc_detach_bshaper_callback()
 *	Call back function for bridge shaper detach
 */
static void nssqdisc_detach_bshaper_callback(void *app_data, struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	if (response->type < 0) {
		nssqdisc_info("%s: B-shaper detach FAILED - response: %d\n",
				__func__, response->type);
		atomic_set(&nq->state, NSSQDISC_STATE_FAILED_RESPONSE);
		return;
	}

	nssqdisc_info("%s: B-shaper detach SUCCESS\n", __func__);
	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_detach_bridge()
 *	Detaches a given bridge shaper from a given interface
 */
static int nssqdisc_detach_bshaper(struct Qdisc *sch, uint32_t if_num)
{
	struct nss_shaper_configure shaper_assign;
	struct nssqdisc_qdisc *nq = (struct nssqdisc_qdisc *)qdisc_priv(sch);
	int32_t state, rc;

	nssqdisc_info("%s: Detaching B-shaper %u from interface %u\n",
			__func__, nq->shaper_id, if_num);

	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: qdisc %p (type %d) is not ready: %d\n",
				__func__, sch, nq->type, state);
		BUG();
	}

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	shaper_assign.interface_num = if_num;
	shaper_assign.i_shaper = false;
	shaper_assign.cb = nssqdisc_detach_bshaper_callback;
	shaper_assign.app_data = sch;
	shaper_assign.owner = THIS_MODULE;
	shaper_assign.type = NSS_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER;
	shaper_assign.mt.unassign_shaper.shaper_num = nq->shaper_id;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_assign);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_warning("%s: Failed to send B-shaper (id: %u) detach "
			"for interface(if_num: %u)\n", __func__, nq->shaper_id, if_num);
		return -1;
	}

	nssqdisc_info("%s: Detach of B-shaper %u to interface %u is complete.",
			__func__, nq->shaper_id, if_num);
	atomic_set(&nq->state, NSSQDISC_STATE_READY);
	return 0;
}

/*
 * nssqdisc_refresh_bshaper_assignment()
 *	Performs assign on unassign of bshaper for interfaces on the bridge.
 */
static int nssqdisc_refresh_bshaper_assignment(struct Qdisc *br_qdisc,
					enum nssqdisc_bshaper_tasks task)
{
	struct net_device *dev;
	struct net_device *br_dev = qdisc_dev(br_qdisc);
	struct nssqdisc_qdisc *nq;
	struct nssqdisc_bridge_update br_update;
	int i;

	if ((br_qdisc->parent != TC_H_ROOT) && (br_qdisc->parent != TC_H_UNSPEC)) {
		nssqdisc_error("%s: Qdisc not root qdisc for the bridge interface: "
				"Handle - %x", __func__, br_qdisc->parent);
		return -1;
	}

	nq = qdisc_priv(br_qdisc);

	/*
	 * Initialize the bridge update srtucture.
	 */
	br_update.port_list_count = 0;
	br_update.unassign_count = 0;

	read_lock(&dev_base_lock);
	dev = first_net_device(&init_net);
	while(dev) {
		struct net_bridge_port *br_port = nssqdisc_get_br_port(dev);
		int nss_if_num;

		nssqdisc_info("%s: Scanning device %s", __func__, dev->name);
		if (!br_port || !br_port->br) {
			goto nextdev;
		}

		/*
		 * Dont care if this device is not on the
		 * bridge that is of concern.
		 */
		if (br_port->br->dev != br_dev) {
			goto nextdev;
		}

		/*
		 * If the interface is known to NSS then we will have to shape it.
		 * Irrespective of whether it has an interface qdisc or not.
		 */
		nss_if_num = nss_get_interface_number(nq->nss_shaping_ctx, dev);
		if (nss_if_num < 0) {
			goto nextdev;
		}

		nssqdisc_info("%s: Will be linking %s to bridge %s\n", __func__,
				dev->name, br_dev->name);
		br_update.port_list[br_update.port_list_count++] = nss_if_num;
nextdev:
		dev = next_net_device(dev);
	}
	read_unlock(&dev_base_lock);

	nssqdisc_info("%s: List count %d\n", __func__, br_update.port_list_count);

	if (task == NSSQDISC_ASSIGN_BSHAPER) {
		/*
		 * Loop through the ports and assign them with B-shapers.
		 */
		for (i = 0; i < br_update.port_list_count; i++) {
			if (nssqdisc_attach_bshaper(br_qdisc, br_update.port_list[i]) >= 0) {
				nssqdisc_info("%s: Interface %u added to bridge %s\n",
					__func__, br_update.port_list[i], br_dev->name);
				continue;
			}
			nssqdisc_error("%s: Unable to attach bshaper with shaper-id: %u, "
				"to interface if_num: %d\n", __func__, nq->shaper_id,
				br_update.port_list[i]);
			br_update.unassign_count = i;
			break;
		}
		nssqdisc_info("%s: Unassign count %d\n", __func__, br_update.unassign_count);
		if (br_update.unassign_count == 0) {
			return 0;
		}

		/*
		 * In case of a failure, unassign the B-shapers that were assigned above
		 */
		for (i = 0; i < br_update.unassign_count; i++) {
			if (nssqdisc_detach_bshaper(br_qdisc, br_update.port_list[i]) >= 0) {
				continue;
			}
			nssqdisc_error("%s: Unable to detach bshaper with shaper-id: %u, "
				"from interface if_num: %d\n", __func__, nq->shaper_id,
				br_update.port_list[i]);
			BUG();
		}

		nssqdisc_info("%s: Failed to link interfaces to bridge\n", __func__);
		return -1;
	} else if (task == NSSQDISC_UNASSIGN_BSHAPER) {
		/*
		 * Loop through the ports and assign them with B-shapers.
		 */
		for (i = 0; i < br_update.port_list_count; i++) {
			if (nssqdisc_detach_bshaper(br_qdisc, br_update.port_list[i]) >= 0) {
				nssqdisc_info("%s: Interface %u removed from bridge %s\n",
					__func__, br_update.port_list[i], br_dev->name);
				continue;
			}
			nssqdisc_error("%s: Unable to detach bshaper with shaper-id: %u, "
				"from interface if_num: %d\n", __func__, nq->shaper_id,
				br_update.port_list[i]);
			BUG();
		}
	}

	return 0;
}

/*
 * nssqdisc_root_cleanup_final()
 *	Performs final cleanup of a root shaper node after all other
 *	shaper node cleanup is complete.
 */
static void nssqdisc_root_cleanup_final(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Root qdisc %p (type %d) final cleanup\n", __func__,
				nq->qdisc, nq->type);

	/*
	 * If we are a bridge then we have to unregister for bridge bouncing
	 * AND destroy the virtual interface that provides bridge shaping.
	 */
	if (nq->is_bridge) {
		/*
		 * Unregister for bouncing to the NSS for bridge shaping
	 	 */
		nssqdisc_info("%s: Unregister for bridge bouncing: %p\n", __func__,
				nq->bounce_context);
		nss_unregister_shaper_bounce_bridge(nq->nss_interface_number);

		/*
		 * Unregister the virtual interface we use to act as shaper
		 * for bridge shaping.
	 	 */
		nssqdisc_info("%s: Release root bridge virtual interface: %p\n",
				__func__, nq->virtual_interface_context);
		nss_destroy_virt_if(nq->virtual_interface_context);
	}

	/*
	 * If we are a virual interface then we have to unregister for interface
	 * bouncing.
	 */
	if (nq->is_virtual) {
		/*
		 * Unregister for interface bouncing of packets
	 	 */
		nssqdisc_info("%s: Unregister for interface bouncing: %p\n",
				__func__, nq->bounce_context);
		nss_unregister_shaper_bounce_interface(nq->nss_interface_number);
	}

	/*
	 * Finally unregister for shaping
	 */
	nssqdisc_info("%s: Unregister for shaping\n", __func__);
	nss_unregister_shaping(nq->nss_shaping_ctx);

	/*
	 * Now set our final state
	 */
	atomic_set(&nq->state, nq->pending_final_state);
}

/*
 * nssqdisc_root_cleanup_shaper_unassign_callback()
 *	Invoked on the response to a shaper unassign config command issued
 */
static void nssqdisc_root_cleanup_shaper_unassign_callback(void *app_data,
					struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq __attribute__ ((unused)) = qdisc_priv(sch);
	nssqdisc_info("%s: Root qdisc %p (type %d) shaper unsassign "
		"response: %d\n", __func__, sch, nq->type, response->type);
	nssqdisc_root_cleanup_final(sch);
}

/*
 * nssqdisc_root_cleanup_shaper_unassign()
 *	Issue command to unassign the shaper
 */
static void nssqdisc_root_cleanup_shaper_unassign(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct nss_shaper_configure shaper_unassign;
	nss_tx_status_t rc;

	nssqdisc_info("%s: Root qdisc %p (type %d): shaper unassign: %d\n",
			__func__, sch, nq->type, nq->shaper_id);

	shaper_unassign.interface_num = nq->nss_interface_number;
	shaper_unassign.i_shaper = (nq->is_bridge)? false : true;
	shaper_unassign.cb = nssqdisc_root_cleanup_shaper_unassign_callback;
	shaper_unassign.app_data = sch;
	shaper_unassign.owner = THIS_MODULE;
	shaper_unassign.type = NSS_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER;
	shaper_unassign.mt.unassign_shaper.shaper_num = nq->shaper_id;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_unassign);
	if (rc == NSS_TX_SUCCESS) {
		return;
	}

	nssqdisc_error("%s: Root qdisc %p (type %d): unassign command send failed: "
		"%d, shaper id: %d\n", __func__, sch, nq->type, rc, nq->shaper_id);

	nssqdisc_root_cleanup_final(sch);
}

/*
 * nssqdisc_root_cleanup_free_node_callback()
 *	Invoked on the response to freeing a shaper node
 */
static void nssqdisc_root_cleanup_free_node_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq __attribute__ ((unused)) = qdisc_priv(sch);
	nssqdisc_info("%s: Root qdisc %p (type %d) free response "
		"type: %d\n", __func__, sch, nq->type, response->type);

	nssqdisc_root_cleanup_shaper_unassign(sch);
}

/*
 * nssqdisc_root_cleanup_free_node()
 *	Free the shaper node, issue command to do so.
 */
static void nssqdisc_root_cleanup_free_node(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct nss_shaper_configure shaper_node_free;
	nss_tx_status_t rc;

	nssqdisc_info("%s: Root qdisc %p (type %d): freeing shaper node\n",
			__func__, sch, nq->type);

	shaper_node_free.interface_num = nq->nss_interface_number;
	shaper_node_free.i_shaper = (nq->is_bridge)? false : true;
	shaper_node_free.cb = nssqdisc_root_cleanup_free_node_callback;
	shaper_node_free.app_data = sch;
	shaper_node_free.owner = THIS_MODULE;
	shaper_node_free.type = NSS_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE;
	shaper_node_free.mt.free_shaper_node.qos_tag = nq->qos_tag;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_node_free);
	if (rc == NSS_TX_SUCCESS) {
		return;
	}

	nssqdisc_error("%s: Qdisc %p (type %d): free command send "
		"failed: %d, qos tag: %x\n", __func__, sch, nq->type,
		rc, nq->qos_tag);

	/*
	 * Move onto unassigning the shaper instead
	 */
	nssqdisc_root_cleanup_shaper_unassign(sch);
}

/*
 * nssqdisc_root_init_root_assign_callback()
 *	Invoked on the response to assigning shaper node as root
 */
static void nssqdisc_root_init_root_assign_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Root assign response for qdisc %p (type %d), "
		"response type: %d\n", __func__, sch, nq->type, response->type);

	if (response->type < 0) {
		nq->pending_final_state = NSSQDISC_STATE_ROOT_SET_FAIL;
		nssqdisc_root_cleanup_free_node(sch);
		return;
	}

	/*
	 * If we are not a root upon a bridge then we are ready
	 */
	if (!nq->is_bridge) {
		nssqdisc_info("%s: Qdisc %p (type %d): set as root and "
			"default, and is READY\n", __func__, sch, nq->type);
		atomic_set(&nq->state, NSSQDISC_STATE_READY);
		return;
	}

	/*
	 * We need to scan the bridge for ports that must have shapers
	 * assigned to them
	 */
	nssqdisc_info("%s: Qdisc %p (type %d): set as root is done. "
		"Bridge update..\n", __func__, sch, nq->type);

	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_root_init_alloc_node_callback()
 *	Invoked on the response to creating a shaper node as root
 */
static void nssqdisc_root_init_alloc_node_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct nss_shaper_configure root_assign;
	nss_tx_status_t rc;

	nssqdisc_info("%s: Qdisc %p (type %d) root alloc node "
		"response type: %d\n", __func__, sch, nq->type,
		response->type);

	if (response->type < 0) {
		nq->pending_final_state = NSSQDISC_STATE_NODE_ALLOC_FAIL;

		/*
		 * No shaper node created, cleanup from unsassigning the shaper
		 */
		nssqdisc_root_cleanup_shaper_unassign(sch);
		return;
	}

	/*
	 * Shaper node has been allocated. Next step is to assign
	 * the shaper node as the root node of our shaper.
	 */
	root_assign.interface_num = nq->nss_interface_number;
	root_assign.i_shaper = (nq->is_bridge)? false : true;
	root_assign.cb = nssqdisc_root_init_root_assign_callback;
	root_assign.app_data = sch;
	root_assign.owner = THIS_MODULE;
	root_assign.type = NSS_SHAPER_CONFIG_TYPE_SET_ROOT;
	root_assign.mt.set_root_node.qos_tag = nq->qos_tag;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &root_assign);
	if (rc == NSS_TX_SUCCESS) {
		return;
	}

	nssqdisc_error("%s: Root assign send command failed: %d\n",
			__func__, rc);

	nq->pending_final_state = NSSQDISC_STATE_ROOT_SET_SEND_FAIL;
	nssqdisc_root_cleanup_free_node(sch);
}

/*
 * nssqdisc_root_init_shaper_assign_callback()
 *	Invoked on the response to a shaper assign config command issued
 */
static void nssqdisc_root_init_shaper_assign_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct nss_shaper_configure shaper_node_create;
	nss_tx_status_t rc;

	nssqdisc_info("%s: Qdisc %p (type %d): shaper assign response type: %d\n",
					__func__, sch, nq->type, response->type);

	if (response->type < 0) {
		/*
		 * Unable to assign a shaper, perform cleanup from final stage
		 */
		nq->pending_final_state = NSSQDISC_STATE_SHAPER_ASSIGN_FAILED;
		nssqdisc_root_cleanup_final(sch);
		return;
	}

	/*
	 * Shaper has been allocated and assigned
	 */
	nq->shaper_id = response->rt.shaper_assign_success.shaper_num;
	nssqdisc_info("%s: Qdisc %p (type %d), shaper assigned: %u\n",
				__func__, sch, nq->type, nq->shaper_id);

	/*
	 * Next step is to allocate our actual shaper node
	 * qos_tag will be the handle we have been given
	 */
	shaper_node_create.interface_num = nq->nss_interface_number;
	shaper_node_create.i_shaper = (nq->is_bridge)? false : true;
	shaper_node_create.cb = nssqdisc_root_init_alloc_node_callback;
	shaper_node_create.app_data = sch;
	shaper_node_create.owner = THIS_MODULE;
	shaper_node_create.type = NSS_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE;
	shaper_node_create.mt.alloc_shaper_node.node_type = nq->type;
	shaper_node_create.mt.alloc_shaper_node.qos_tag = nq->qos_tag;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_node_create);
	if (rc == NSS_TX_SUCCESS) {
		return;
	}

	/*
	 * Unable to send alloc node command, cleanup from unassigning the shaper
	 */
	nssqdisc_error("%s: Qdisc %p (type %d) create command failed: %d\n",
			__func__, sch, nq->type, rc);

	nq->pending_final_state = NSSQDISC_STATE_NODE_ALLOC_SEND_FAIL;
	nssqdisc_root_cleanup_shaper_unassign(sch);
}


/*
 * nssqdisc_child_cleanup_final()
 *	Perform final cleanup of a shaper node after all shaper node
 *	cleanup is complete.
 */
static void nssqdisc_child_cleanup_final(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Final cleanup type %d: %p\n", __func__,
			nq->type, sch);

	/*
	 * Finally unregister for shaping
	 */
	nssqdisc_info("%s: Unregister for shaping\n", __func__);
	nss_unregister_shaping(nq->nss_shaping_ctx);

	/*
	 * Now set our final state
	 */
	atomic_set(&nq->state, nq->pending_final_state);
}


/*
 * nssqdisc_child_cleanup_free_node_callback()
 *	Invoked on the response to freeing a child shaper node
 */
static void nssqdisc_child_cleanup_free_node_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq __attribute__((unused)) = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d): child free response type: %d\n",
			__func__, sch, nq->type, response->type);

	if (response->type < 0) {
		nssqdisc_error("%s: Qdisc %p (type %d): free shaper node failed\n",
				__func__, sch, nq->type);
	} else {
		nssqdisc_info("%s: Qdisc %p (type %d): child shaper node "
				"free complete\n", __func__, sch, nq->type);
	}

	/*
	 * Perform final cleanup
	 */
	nssqdisc_child_cleanup_final(sch);
}

/*
 * nssqdisc_child_cleanup_free_node()
 *	Free the child shaper node, issue command to do so.
 */
static void nssqdisc_child_cleanup_free_node(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct nss_shaper_configure shaper_node_free;
	nss_tx_status_t rc;

	nssqdisc_info("%s: Qdisc %p (type %d): free shaper node command\n",
			__func__, sch, nq->type);

	shaper_node_free.interface_num = nq->nss_interface_number;
	shaper_node_free.i_shaper = (nq->is_bridge)? false : true;
	shaper_node_free.cb = nssqdisc_child_cleanup_free_node_callback;
	shaper_node_free.app_data = sch;
	shaper_node_free.owner = THIS_MODULE;
	shaper_node_free.type = NSS_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE;
	shaper_node_free.mt.free_shaper_node.qos_tag = nq->qos_tag;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_node_free);
	if (rc == NSS_TX_SUCCESS) {
		return;
	}

	nssqdisc_error("%s: Qdisc %p (type %d): child free node command send "
			"failed: %d, qos tag: %x\n", __func__, sch, nq->type,
			rc, nq->qos_tag);

	/*
	 * Perform final cleanup
	 */
	nssqdisc_child_cleanup_final(sch);
}

/*
 * nssqdisc_child_init_alloc_node_callback()
 *	Invoked on the response to creating a child shaper node
 */
static void nssqdisc_child_init_alloc_node_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d): child alloc node, response "
		"type: %d\n", __func__, sch, nq->type, response->type);

	if (response->type < 0) {
		/*
		 * Cleanup from final stage
		 */
		nq->pending_final_state = NSSQDISC_STATE_NODE_ALLOC_FAIL_CHILD;
		nssqdisc_child_cleanup_final(sch);
		return;
	}

	/*
	 * Shaper node has been allocated
	 */
	nssqdisc_info("%s: Qdisc %p (type %d): shaper node successfully "
			"created as a child node\n",__func__, sch, nq->type);

	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_bounce_callback()
 *	Enqueues packets bounced back from NSS firmware.
 */
static void nssqdisc_bounce_callback(void *app_data, struct sk_buff *skb)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;

	/*
	 * All we have to do is enqueue for transmit and schedule a dequeue
	 */
	__qdisc_enqueue_tail(skb, sch, &sch->q);
	__netif_schedule(sch);
}

/*
 * nssqdisc_peek()
 *	Called to peek at the head of an nss qdisc
 */
static struct sk_buff *nssqdisc_peek(struct Qdisc *sch)
{
	return skb_peek(&sch->q);
}

/*
 * nssqdisc_drop()
 *	Called to drop the packet at the head of queue
 */
static unsigned int nssqdisc_drop(struct Qdisc *sch)
{
	return __qdisc_queue_drop_head(sch, &sch->q);
}

/*
 * nssqdisc_reset()
 *	Called when a qdisc is reset
 */
static void nssqdisc_reset(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq __attribute__ ((unused)) = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d) resetting\n",
			__func__, sch, nq->type);

	/*
	 * Delete all packets pending in the output queue and reset stats
	 */
	qdisc_reset_queue(sch);
}

/*
 * nssqdisc_enqueue()
 *	Generic enqueue call for enqueuing packets into NSS for shaping
 */
static int nssqdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	nss_tx_status_t status;

	/*
	 * If we are not the root qdisc then we should not be getting packets!!
	 */
	if (!nq->is_root) {
		nssqdisc_warning("%s: Qdisc %p (type %d): unexpected packet "
			"for child qdisc - skb: %p\n", __func__, sch, nq->type, skb);
		__qdisc_enqueue_tail(skb, sch, &sch->q);
		__netif_schedule(sch);
		return NET_XMIT_SUCCESS;
	}

	/*
	 * Packet enueued in linux for transmit.
	 *
	 * What we do here depends upon whether we are a bridge or not. If not a
	 * bridge then it depends on if we are a physical or virtual interface
	 * The decision we are trying to reach is whether to bounce a packet to
	 * the NSS to be shaped or not.
	 *
	 * is_bridge		is_virtual	Meaning
	 * ---------------------------------------------------------------------------
	 * false		false		Physical interface in NSS
	 *
	 * Action: Simply allow the packet to be dequeued. The packet will be
	 * shaped by the interface shaper in the NSS by the usual transmit path.
	 *
	 *
	 * false		true		Physical interface in Linux.
	 * 					NSS still responsible for shaping
	 *
	 * Action: Bounce the packet to the NSS virtual interface that represents
	 * this Linux physical interface for INTERFACE shaping. When the packet is
	 * returned from being shaped we allow it to be dequeued for transmit.
	 *
	 * true			n/a		Logical Linux interface.
	 *					Root qdisc created a virtual interface
	 *					to represent it in the NSS for shaping
	 *					purposes.
	 *
	 * Action: Bounce the packet to the NSS virtual interface (for BRIDGE shaping)
	 * the bridge root qdisc created for it. When the packet is returned from being
	 * shaped we allow it to be dequeued for transmit.
	 */

	if (!nq->is_bridge && !nq->is_virtual) {
		/*
		 * TX to an NSS physical - the shaping will occur as part of normal
		 * transmit path.
		 */
		__qdisc_enqueue_tail(skb, sch, &sch->q);
		__netif_schedule(sch);
		return NET_XMIT_SUCCESS;
	}

	if (!nq->is_bridge && nq->is_virtual) {
		/*
		 * TX to a physical Linux (NSS virtual).  Bounce packet to NSS for
		 * interface shaping.
		 */
		nss_tx_status_t status = nss_shaper_bounce_interface_packet(nq->bounce_context,
								nq->nss_interface_number, skb);
		if (status != NSS_TX_SUCCESS) {
			/*
			 * Just transmit anyway, don't want to loose the packet
			 */
			nssqdisc_warning("%s: Qdisc %p (type %d): failed to bounce for "
				"interface: %d, skb: %p\n", __func__, sch, nq->type,
				nq->nss_interface_number, skb);

			__qdisc_enqueue_tail(skb, sch, &sch->q);
			__netif_schedule(sch);
		}
		return NET_XMIT_SUCCESS;
	}

	/*
	 * TX to a bridge, this is to be shaped by the b shaper on the virtual interface created
	 * to represent the bridge interface.
	 */
	status = nss_shaper_bounce_bridge_packet(nq->bounce_context, nq->nss_interface_number, skb);
	if (status != NSS_TX_SUCCESS) {
		/*
		 * Just transmit anyway, don't want to loose the packet
		 */
		nssqdisc_warning("%s: Qdisc %p (type %d): failed to bounce for bridge %d, skb: %p\n",
					__func__, sch, nq->type, nq->nss_interface_number, skb);
		__qdisc_enqueue_tail(skb, sch, &sch->q);
		__netif_schedule(sch);
	}
	return NET_XMIT_SUCCESS;
}

/*
 * nssqdisc_dequeue()
 *	Generic dequeue call for dequeuing bounced packets.
 */
static struct sk_buff *nssqdisc_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;

	/*
	 * We use __skb_dequeue() to ensure that
	 * stats don't get updated twice.
	 */
	skb = __skb_dequeue(&sch->q);

	return skb;
}

/*
 * nssqdisc_set_default_callback()
 *	The callback function for a shaper node set default
 */
static void nssqdisc_set_default_callback(void *app_data,
			struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node set default, response type: %d\n",
			__func__, sch, nq->type, response->type);

	if (response->type < 0) {
		atomic_set(&nq->state, NSSQDISC_STATE_FAILED_RESPONSE);
		return;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): attach complete\n", __func__, sch, nq->type);
	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_node_set_default()
 *	Configuration function that sets shaper node as default for packet enqueue
 */
static int nssqdisc_set_default(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct nss_shaper_configure shaper_node_default;
	int32_t state, rc;

	nssqdisc_info("%s: Setting qdisc %p (type %d) as default\n", __func__,
			sch, nq->type);

	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: Qdisc %p (type %d): not ready: %d\n", __func__,
				sch, nq->type, state);
		BUG();
	}

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	shaper_node_default.interface_num = nq->nss_interface_number;
	shaper_node_default.i_shaper = (nq->is_bridge)? false : true;
	shaper_node_default.cb = nssqdisc_set_default_callback;
	shaper_node_default.app_data = sch;
	shaper_node_default.owner = THIS_MODULE;
	shaper_node_default.type = NSS_SHAPER_CONFIG_TYPE_SET_DEFAULT;
	shaper_node_default.mt.set_default_node.qos_tag = nq->qos_tag;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_node_default);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_warning("%s: Failed to send set default message for "
					"qdisc type %d\n", __func__, nq->type);
		return -1;
	}

	/*
	 * Wait until cleanup operation is complete at which point the state
	 * shall become idle. NOTE: This relies on the NSS driver to be able
	 * to operate asynchronously which means kernel preemption is required.
	 */
	while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
		yield();
	}

	if (state == NSSQDISC_STATE_FAILED_RESPONSE) {
		nssqdisc_error("%s: Qdisc %p (type %d): failed to default "
			"State: %d\n", __func__, sch, nq->type, state);
		return -1;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node default complete\n",
			__func__, sch, nq->type);
	return 0;
}

/*
 * nssqdisc_node_attach_callback()
 *	The callback function for a shaper node attach message
 */
static void nssqdisc_node_attach_callback(void *app_data,
			struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d) shaper node attach response "
			"type: %d\n", __func__, sch, nq->type, response->type);
	if (response->type < 0) {
		atomic_set(&nq->state, NSSQDISC_STATE_FAILED_RESPONSE);
		return;
	}

	nssqdisc_info("%s: qdisc type %d: %p, attach complete\n", __func__,
			nq->type, sch);

	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_node_attach()
 *	Configuration function that helps attach a child shaper node to a parent.
 */
static int nssqdisc_node_attach(struct Qdisc *sch,
	struct nss_shaper_configure *shaper_node_attach, int32_t attach_type)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	int32_t state, rc;

	nssqdisc_info("%s: Qdisc %p (type %d) attaching\n",
			__func__, sch, nq->type);

	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: Qdisc %p (type %d): not ready, state: %d\n",
				__func__, sch, nq->type, state);
		BUG();
	}

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	shaper_node_attach->interface_num = nq->nss_interface_number;
	shaper_node_attach->i_shaper = (nq->is_bridge)? false : true;
	shaper_node_attach->cb = nssqdisc_node_attach_callback;
	shaper_node_attach->app_data = sch;
	shaper_node_attach->owner = THIS_MODULE;
	shaper_node_attach->type = attach_type;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, shaper_node_attach);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_warning("%s: Failed to send configure message for "
					"qdisc type %d\n", __func__, nq->type);
		return -1;
	}

	/*
	 * Wait until cleanup operation is complete at which point the state
	 * shall become idle. NOTE: This relies on the NSS driver to be able
	 * to operate asynchronously which means kernel preemption is required.
	 */
	while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
		yield();
	}

	if (state == NSSQDISC_STATE_FAILED_RESPONSE) {
		nssqdisc_error("%s: Qdisc %p (type %d) failed to attach child "
			"node, State: %d\n", __func__, sch, nq->type, state);
		return -1;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node attach complete\n",
			__func__, sch, nq->type);
	return 0;
}

/*
 * nssqdisc_node_detach_callback()
 *	The callback function for a shaper node detach message
 */
static void nssqdisc_node_detach_callback(void *app_data,
			struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node detach response "
			"type: %d\n", __func__, sch, nq->type, response->type);

	if (response->type < 0) {
		atomic_set(&nq->state, NSSQDISC_STATE_FAILED_RESPONSE);
		return;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): detach complete\n",
			__func__, sch, nq->type);

	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_detach()
 *	Configuration function that helps detach a child shaper node to a parent.
 */
static int nssqdisc_node_detach(struct Qdisc *sch,
	struct nss_shaper_configure *shaper_node_detach, int32_t detach_type)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	int32_t state, rc;

	nssqdisc_info("%s: Qdisc %p (type %d) detaching\n",
			__func__, sch, nq->type);

	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: Qdisc %p (type %d): not ready, state: %d\n",
				__func__, sch, nq->type, state);
		BUG();
	}

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	shaper_node_detach->interface_num = nq->nss_interface_number;
	shaper_node_detach->i_shaper = (nq->is_bridge)? false : true;
	shaper_node_detach->cb = nssqdisc_node_detach_callback;
	shaper_node_detach->app_data = sch;
	shaper_node_detach->owner = THIS_MODULE;
	shaper_node_detach->type = detach_type;

	rc = nss_shaper_config_send(nq->nss_shaping_ctx, shaper_node_detach);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_warning("%s: Qdisc %p (type %d): Failed to send configure "
					"message.", __func__, sch, nq->type);
		return -1;
	}

	/*
	 * Wait until cleanup operation is complete at which point the state shall become idle.
	 * NOTE: This relies on the NSS driver to be able to operate asynchronously which means
	 * kernel preemption is required.
	 */
	while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
		yield();
	}

	if (state == NSSQDISC_STATE_FAILED_RESPONSE) {
		nssqdisc_error("%s: Qdisc %p (type %d): failed to attach child node, "
				"State: %d\n", __func__, sch, nq->type, state);
		return -1;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node detach complete\n",
			__func__, sch, nq->type);
	return 0;
}

/*
 * nssqdisc_configure_callback()
 *	The call back function for a shaper node configure message
 */
static void nssqdisc_configure_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *sch = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node configure "
		"response type: %d\n", __func__, sch, nq->type, response->type);

	if (response->type < 0) {
		atomic_set(&nq->state, NSSQDISC_STATE_FAILED_RESPONSE);
		return;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): configuration complete\n",
			__func__, sch, nq->type);
	atomic_set(&nq->state, NSSQDISC_STATE_READY);
}

/*
 * nssqdisc_configure()
 *	Configuration function that aids in tuning of queuing parameters.
 */
static int nssqdisc_configure(struct Qdisc *sch,
	struct nss_shaper_configure *shaper_node_configure, int32_t config_type)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	int32_t state, rc;

	nssqdisc_info("%s: Qdisc %p (type %d) configuring\n", __func__, sch, nq->type);

	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: Qdisc %p (type %d): not ready for configure, "
			"state : %d\n", __func__, sch, nq->type, state);
		BUG();
	}

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	shaper_node_configure->interface_num = nq->nss_interface_number;
	shaper_node_configure->i_shaper = (nq->is_bridge)? false : true;
	shaper_node_configure->cb = nssqdisc_configure_callback;
	shaper_node_configure->app_data = sch;
	shaper_node_configure->owner = THIS_MODULE;
	shaper_node_configure->type = config_type;

	nssqdisc_info("Sending config type %d\n", config_type);
	rc = nss_shaper_config_send(nq->nss_shaping_ctx, shaper_node_configure);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_warning("%s: Qdisc %p (type %d): Failed to send configure "
			"message\n", __func__, sch, nq->type);
		return -1;
	}

	/*
	 * Wait until cleanup operation is complete at which point the state
	 * shall become idle. NOTE: This relies on the NSS driver to be able
	 * to operate asynchronously which means kernel preemption is required.
	 */
	while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
		yield();
	}

	if (state == NSSQDISC_STATE_FAILED_RESPONSE) {
		nssqdisc_error("%s: Qdisc %p (type %d): failed to configure shaper "
			"node: State: %d\n", __func__, sch, nq->type, state);
		atomic_set(&nq->state, NSSQDISC_STATE_READY);
		return -1;
	}

	nssqdisc_info("%s: Qdisc %p (type %d): shaper node configure complete\n",
			__func__, sch, nq->type);
	return 0;
}

/*
 * nssqdisc_destroy()
 *	Destroys a shaper in NSS, and the sequence is based on the position of
 *	this qdisc (child or root) and the interface to which it is attached to.
 */
static void nssqdisc_destroy(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	int32_t state;

	nssqdisc_info("%s: Qdisc %p (type %d) destroy\n",
			__func__, sch, nq->type);


	state = atomic_read(&nq->state);
	if (state != NSSQDISC_STATE_READY) {
		nssqdisc_error("%s: Qdisc %p (type %d): destroy not ready, "
				"state: %d\n", __func__, sch, nq->type, state);
		BUG();
	}

	/*
	 * How we begin to tidy up depends on whether we are root or child
	 */
	nq->pending_final_state = NSSQDISC_STATE_IDLE;
	if (nq->is_root) {

		/*
		 * If this is root on a bridge interface, then unassign
		 * the bshaper from all the attached interfaces.
		 */
		if (nq->is_bridge) {
			nssqdisc_info("%s: Qdisc %p (type %d): is root on bridge. Need to "
				"unassign bshapers from its interfaces\n", __func__, sch, nq->type);
			nssqdisc_refresh_bshaper_assignment(sch, NSSQDISC_UNASSIGN_BSHAPER);
		}

		/*
		 * Begin by freeing the root shaper node
		 */
		nssqdisc_root_cleanup_free_node(sch);
	} else {
		/*
		 * Begin by freeing the child shaper node
		 */
		nssqdisc_child_cleanup_free_node(sch);
	}

	/*
	 * Wait until cleanup operation is complete at which point the state
	 * shall become idle. NOTE: This relies on the NSS driver to be able
	 * to operate asynchronously which means kernel preemption is required.
	 */
	while (NSSQDISC_STATE_IDLE != (state = atomic_read(&nq->state))) {
		yield();
	}

	if (nq->destroy_virtual_interface) {
		nss_destroy_virt_if((void *)nq->nss_interface_number);
	}

	nssqdisc_info("%s: Qdisc %p (type %d): destroy complete\n",
			__func__, sch, nq->type);
}


/*
 * nssqdisc_init()
 *	Initializes a shaper in NSS, based on the position of this qdisc (child or root)
 *	and if its a normal interface or a bridge interface.
 */
static int nssqdisc_init(struct Qdisc *sch, nss_shaper_node_type_t type)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);
	struct Qdisc *root;
	u32 parent;
	nss_tx_status_t rc;
	struct net_device *dev;
	int32_t state;
	struct nss_shaper_configure shaper_assign;

	/*
	 * Record our qdisc and type in the private region for handy use
	 */
	nq->qdisc = sch;
	nq->type = type;

	/*
	 * We dont have to destroy a virtual interface unless
	 * we are the ones who created it. So set it to false
	 * as default.
	 */
	nq->destroy_virtual_interface = false;

	/*
	 * Set shaper node state to IDLE
	 */
	atomic_set(&nq->state, NSSQDISC_STATE_IDLE);

	nq->qos_tag = (uint32_t)sch->handle >> 16;

	/*
	 * The root must be of an nss type (unless we are of course going to be root).
	 * This is to prevent mixing NSS qdisc with other types of qdisc.
	 */
	parent = sch->parent;
	root = qdisc_root(sch);
	nssqdisc_info("%s: Qdisc %p (type %d) init root: %p, me: %p, my handle: %x, "
		"parent: %x rootid: %s owner: %p\n", __func__, sch, nq->type, root,
		sch, nq->qos_tag, parent, root->ops->id, root->ops->owner);

	if ((parent != TC_H_ROOT) && (root->ops->owner != THIS_MODULE)) {
		nssqdisc_error("%s: Qdisc %p (type %d) used outside of NSS shaping "
			"framework. Parent: %x ops: %p Our Module: %p\n", __func__,
			sch, nq->type, parent, root->ops, THIS_MODULE);

		atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
		return -1;
	}

	/*
	 * Register for NSS shaping
	 */
	nq->nss_shaping_ctx = nss_register_shaping();
	if (!nq->nss_shaping_ctx) {
		nssqdisc_error("%s: no shaping context returned for type %d\n",
				__func__, nq->type);
		atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
		return -1;
	}

	/*
	 * Are we the root qdisc?
	 */
	if (parent == TC_H_ROOT) {
		nssqdisc_info("%s: Qdisc %p (type %d) is root\n", __func__, sch, nq->type);
		nq->is_root = true;
	} else {
		nssqdisc_info("%s: Qdisc %p (type %d) not root\n", __func__, sch, nq->type);
		nq->is_root = false;
	}

	/*
	 * Get the net device as it will tell us if we are on a bridge,
	 * or on a net device that is represented by a virtual NSS interface (e.g. WIFI)
	 */
	dev = qdisc_dev(sch);
	nssqdisc_info("%s: Qdisc %p (type %d) init dev: %p\n", __func__, sch, nq->type, dev);

	/*
	 * Determine if dev is a bridge or not as this determines if we
	 * interract with an I or B shaper
	 */
	if (dev->priv_flags == IFF_EBRIDGE) {
		nssqdisc_info("%s: Qdisc %p (type %d) init qdisc: %p, is bridge\n",
			__func__, sch, nq->type, nq->qdisc);
		nq->is_bridge = true;
	} else {
		nssqdisc_info("%s: Qdisc %p (type %d) init qdisc: %p, not bridge\n",
			__func__, sch, nq->type, nq->qdisc);
		nq->is_bridge = false;
	}

	/*
	 * If we are not the root qdisc then we have a simple enough job to do
	 */
	if (!nq->is_root) {
		struct nss_shaper_configure shaper_node_create;

		nssqdisc_info("%s: Qdisc %p (type %d) initializing non-root qdisc\n",
				__func__, sch, nq->type);

		/*
		 * The device we are operational on MUST be recognised as an NSS interface.
		 * NOTE: We do NOT support non-NSS known interfaces in this implementation.
		 * NOTE: This will still work where the dev is registered as virtual, in which case
		 * nss_interface_number shall indicate a virtual NSS interface.
		 */
		nq->nss_interface_number = nss_get_interface_number(nq->nss_shaping_ctx, dev);
		if (nq->nss_interface_number < 0) {
			nssqdisc_error("%s: Qdisc %p (type %d) net device unknown to "
				"nss driver %s\n", __func__, sch, nq->type, dev->name);
			nss_unregister_shaping(nq->nss_shaping_ctx);
			atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
			return -1;
		}

		/*
		 * Create a shaper node for requested type.
		 * Essentially all we need to do is create the shaper node.
		 */
		nssqdisc_info("%s: Qdisc %p (type %d) non-root (child) create\n",
				__func__, sch, nq->type);

		shaper_node_create.interface_num = nq->nss_interface_number;
		shaper_node_create.i_shaper = (nq->is_bridge)? false : true;
		shaper_node_create.cb = nssqdisc_child_init_alloc_node_callback;
		shaper_node_create.app_data = sch;
		shaper_node_create.owner = THIS_MODULE;
		shaper_node_create.type = NSS_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE;
		shaper_node_create.mt.alloc_shaper_node.node_type = nq->type;
		shaper_node_create.mt.alloc_shaper_node.qos_tag = nq->qos_tag;

		rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_node_create);
		if (rc != NSS_TX_SUCCESS) {
			nssqdisc_error("%s: Qdisc %p (type %d) create command "
				"failed: %d\n", __func__, sch, nq->type, rc);
			nq->pending_final_state = NSSQDISC_STATE_CHILD_ALLOC_SEND_FAIL;
			nssqdisc_child_cleanup_final(sch);
			return -1;
		}

		/*
		 * Wait until init operation is complete.
		 * NOTE: This relies on the NSS driver to be able to operate
		 * asynchronously which means kernel preemption is required.
		 */
		while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
			yield();
		}
		nssqdisc_info("%s: Qdisc %p (type %d): initialised with state: %d\n",
					__func__, sch, nq->type, state);
		if (state > 0) {
			return 0;
		}
		return -1;
	}

	/*
	 * Root qdisc has a lot of work to do. It is responsible for setting up
	 * the shaper and creating the root and default shaper nodes. Also, when
	 * operating on a bridge, a virtual NSS interface is created to represent
	 * bridge shaping. Further, when operating on a bridge, we monitor for
	 * bridge port changes and assign B shapers to the interfaces of the ports.
	 */
	nssqdisc_info("%s: init qdisc type %d : %p, ROOT\n", __func__, nq->type, sch);

	/*
	 * Detect if we are operating on a bridge or interface
	 */
	if (nq->is_bridge) {
		nssqdisc_info("%s: Qdisc %p (type %d): initializing root qdisc on "
			"bridge\n", __func__, sch, nq->type);

		/*
		 * As we are a root qdisc on this bridge then we have to create a
		 * virtual interface to represent this bridge in the NSS. This will
		 * allow us to bounce packets to the NSS for bridge shaping action.
		 * Also set the destroy virtual interface flag so that it is destroyed
		 * when the module goes down. If this is not done, the OS waits for
		 * the interface to be released.
		 */
		nq->virtual_interface_context = nss_create_virt_if(dev);
		nq->destroy_virtual_interface = true;
		if (!nq->virtual_interface_context) {
			nssqdisc_error("%s: Qdisc %p (type %d): cannot create virtual "
				"interface\n", __func__, sch, nq->type);
			nss_unregister_shaping(nq->nss_shaping_ctx);
			atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
			return -1;
		}
		nssqdisc_info("%s: Qdisc %p (type %d): virtual interface registered "
			"in NSS: %p\n", __func__, sch, nq->type, nq->virtual_interface_context);
		nq->nss_interface_number = nss_virt_if_get_interface_num(nq->virtual_interface_context);
		nssqdisc_info("%s: Qdisc %p (type %d) virtual interface number: %d\n",
				__func__, sch, nq->type, nq->nss_interface_number);

		/*
		 * The root qdisc will get packets enqueued to it, so it must
		 * register for bridge bouncing as it will be responsible for
		 * bouncing packets to the NSS for bridge shaping.
		 */
		nq->bounce_context = nss_register_shaper_bounce_bridge(nq->nss_interface_number,
							nssqdisc_bounce_callback, sch, THIS_MODULE);
		if (!nq->bounce_context) {
			nssqdisc_error("%s: Qdisc %p (type %d): root but cannot register "
					"for bridge bouncing\n", __func__, sch, nq->type);
			nss_destroy_virt_if(nq->virtual_interface_context);
			nss_unregister_shaping(nq->nss_shaping_ctx);
			atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
			return -1;
		}

	} else {
		nssqdisc_info("%s: Qdisc %p (type %d): is interface\n", __func__, sch, nq->type);

		/*
		 * The device we are operational on MUST be recognised as an NSS interface.
		 * NOTE: We do NOT support non-NSS known interfaces in this basic implementation.
		 * NOTE: This will still work where the dev is registered as virtual, in which case
		 * nss_interface_number shall indicate a virtual NSS interface.
		 */
		nq->nss_interface_number = nss_get_interface_number(nq->nss_shaping_ctx, dev);
		if (nq->nss_interface_number < 0) {
			nssqdisc_error("%s: Qdisc %p (type %d): interface unknown to nss driver %s\n",
					__func__, sch, nq->type, dev->name);
			nss_unregister_shaping(nq->nss_shaping_ctx);
			atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
			return -1;
		}

		/*
		 * Is the interface virtual or not?
		 * NOTE: If this interface is virtual then we have to bounce packets to it for shaping
		 */
		nq->is_virtual = nss_interface_is_virtual(nq->nss_shaping_ctx, nq->nss_interface_number);
		if (!nq->is_virtual) {
			nssqdisc_info("%s: Qdisc %p (type %d): interface %u is physical\n",
					__func__, sch, nq->type, nq->nss_interface_number);
		} else {
			nssqdisc_info("%s: Qdisc %p (type %d): interface %u is virtual\n",
					__func__, sch, nq->type, nq->nss_interface_number);

			/*
			 * Register for interface bounce shaping.
			 */
			nq->bounce_context = nss_register_shaper_bounce_interface(nq->nss_interface_number,
								nssqdisc_bounce_callback, sch, THIS_MODULE);
			if (!nq->bounce_context) {
				nssqdisc_error("%s: Qdisc %p (type %d): is root but failed "
				"to register for interface bouncing\n", __func__, sch, nq->type);
				nss_unregister_shaping(nq->nss_shaping_ctx);
				atomic_set(&nq->state, NSSQDISC_STATE_INIT_FAILED);
				return -1;
			}
		}
	}

	/*
	 * We need to issue a command to establish a shaper on the interface.
	 */
	shaper_assign.interface_num = nq->nss_interface_number;
	shaper_assign.i_shaper = (nq->is_bridge)? false : true;
	shaper_assign.cb = nssqdisc_root_init_shaper_assign_callback;
	shaper_assign.app_data = sch;
	shaper_assign.owner = THIS_MODULE;
	shaper_assign.type = NSS_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER;
	shaper_assign.mt.assign_shaper.shaper_num = 0;	/* Any free shaper will do */
	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &shaper_assign);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_error("%s: shaper assign command failed: %d\n", __func__, rc);
		nq->pending_final_state = NSSQDISC_STATE_ASSIGN_SHAPER_SEND_FAIL;
		nssqdisc_root_cleanup_final(sch);
		if (nq->destroy_virtual_interface) {
			nss_destroy_virt_if(nq->virtual_interface_context);
		}
		return -1;
	}

	/*
	 * Wait until init operation is complete.
	 * NOTE: This relies on the NSS driver to be able to operate asynchronously which means
	 * kernel preemption is required.
	 */
	nssqdisc_info("%s: Qdisc %p (type %d): Waiting on response from NSS for "
			"shaper assign message\n", __func__, sch, nq->type);
	while (NSSQDISC_STATE_IDLE == (state = atomic_read(&nq->state))) {
		yield();
	}
	nssqdisc_info("%s: Qdisc %p (type %d): is initialised with state: %d\n",
			__func__, sch, nq->type, state);

	if (state > 0) {

		/*
		 * Return if this is not a root qdisc on a bridge interface.
		 */
		if (!nq->is_root || !nq->is_bridge) {
			return 0;
		}

		nssqdisc_info("%s: This is a bridge interface. Linking bridge ...\n",
				__func__);
		/*
		 * This is a root qdisc added to a bridge interface. Now we go ahead
		 * and add this B-shaper to interfaces known to the NSS
		 */
		if (nssqdisc_refresh_bshaper_assignment(sch, NSSQDISC_ASSIGN_BSHAPER) < 0) {
			nssqdisc_destroy(sch);
			nssqdisc_error("%s: Bridge linking failed\n", __func__);
			return -1;
		}
		nssqdisc_info("%s: Bridge linking complete\n", __func__);
		return 0;
	}

	/*
	 * Destroy any virtual interfaces created by us before returning a failure.
	 */
	if (nq->destroy_virtual_interface) {
		nss_destroy_virt_if(nq->virtual_interface_context);
	}

	return -1;
}

/*
 * nssqdisc_basic_stats_callback()
 *	Invoked after getting basic stats
 */
static void nssqdisc_basic_stats_callback(void *app_data,
				struct nss_shaper_response *response)
{
	struct Qdisc *qdisc = (struct Qdisc *)app_data;
	struct nssqdisc_qdisc *nq = qdisc_priv(qdisc);

	if (response->type < 0) {
		nssqdisc_info("%s: Qdisc %p (type %d): Received stats - "
			"response: type: %d\n", __func__, qdisc, nq->type,
			response->type);
		atomic_sub(1, &nq->pending_stat_requests);
		return;
	}

	/*
	 * Record latest basic stats
	 */
	nq->basic_stats_latest = response->rt.shaper_node_basic_stats_get_success;

	/*
	 * Update qdisc->bstats
	 */
	qdisc->bstats.bytes += (__u64)nq->basic_stats_latest.delta.dequeued_bytes;
	qdisc->bstats.packets += nq->basic_stats_latest.delta.dequeued_packets;

	/*
	 * Update qdisc->qstats
	 */
	qdisc->qstats.backlog = nq->basic_stats_latest.qlen_bytes;
	qdisc->q.qlen = nq->basic_stats_latest.qlen_packets;

	qdisc->qstats.drops += (nq->basic_stats_latest.delta.enqueued_packets_dropped +
				nq->basic_stats_latest.delta.dequeued_packets_dropped);

	/*
	 * Update qdisc->qstats
	 */
	qdisc->qstats.qlen = qdisc->limit;
	qdisc->qstats.requeues = 0;
	qdisc->qstats.overlimits += nq->basic_stats_latest.delta.queue_overrun;

	if (atomic_read(&qdisc->refcnt) == 0) {
		atomic_sub(1, &nq->pending_stat_requests);
		return;
	}

	/*
	 * Requests for stats again, after 1 sec.
	 */
	nq->stats_get_timer.expires += HZ;
	if (nq->stats_get_timer.expires <= jiffies) {
		nssqdisc_error("losing time %lu, jiffies = %lu\n",
				nq->stats_get_timer.expires, jiffies);
		nq->stats_get_timer.expires = jiffies + HZ;
	}
	add_timer(&nq->stats_get_timer);
}

/*
 * nssqdisc_get_stats_timer_callback()
 *	Invoked periodically to get updated stats
 */
static void nssqdisc_get_stats_timer_callback(unsigned long int data)
{
	struct Qdisc *qdisc = (struct Qdisc *)data;
	struct nssqdisc_qdisc *nq = qdisc_priv(qdisc);
	nss_tx_status_t rc;
	struct nss_shaper_configure basic_stats_get;

	/*
	 * Issue command to get stats
	 * Stats still in progress?  If not then send a new poll
	 */
	basic_stats_get.interface_num = nq->nss_interface_number;
	basic_stats_get.i_shaper = (nq->is_bridge)? false : true;
	basic_stats_get.cb = nssqdisc_basic_stats_callback;
	basic_stats_get.app_data = qdisc;
	basic_stats_get.owner = THIS_MODULE;
	basic_stats_get.type = NSS_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET;
	basic_stats_get.mt.shaper_node_basic_stats_get.qos_tag = nq->qos_tag;
	rc = nss_shaper_config_send(nq->nss_shaping_ctx, &basic_stats_get);
	if (rc != NSS_TX_SUCCESS) {
		nssqdisc_error("%s: %p: basic stats get failed to send\n",
				__func__, qdisc);
		atomic_sub(1, &nq->pending_stat_requests);
	}
}

/*
 * nssqdisc_start_basic_stats_polling()
 *	Call to initiate the stats polling timer
 */
static void nssqdisc_start_basic_stats_polling(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	init_timer(&nq->stats_get_timer);
	nq->stats_get_timer.function = nssqdisc_get_stats_timer_callback;
	nq->stats_get_timer.data = (unsigned long)sch;
	nq->stats_get_timer.expires = jiffies + HZ;
	atomic_set(&nq->pending_stat_requests, 1);
	add_timer(&nq->stats_get_timer);
}

/*
 * nssqdisc_stop_basic_stats_polling()
 *	Call to stop polling of basic stats
 */
static void nssqdisc_stop_basic_stats_polling(struct Qdisc *sch)
{
	struct nssqdisc_qdisc *nq = qdisc_priv(sch);

	/*
	 * We wait until we have received the final stats
	 */
	while (atomic_read(&nq->pending_stat_requests) != 0) {
		yield();
	}
}

/*
 * nssqdisc_if_event_cb()
 *	Callback function that is registered to listen to events on net_device.
 */
static int nssqdisc_if_event_cb(struct notifier_block *unused,
					unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;
	struct net_device *br;
	struct Qdisc *br_qdisc;
	int if_num, br_num;

	switch (event) {
	case NETDEV_BR_JOIN:
		nssqdisc_info("Reveived NETDEV_BR_JOIN on interface %s\n",
				dev->name);
	case NETDEV_BR_LEAVE:
		nssqdisc_info("Reveived NETDEV_BR_LEAVE on interface %s\n",
				dev->name);
		br = dev->master;
		if_num = nss_get_interface_number(nssqdisc_ctx, dev);

		if (br == NULL || br->priv_flags != IFF_EBRIDGE) {
			nssqdisc_error("Sensed bridge activity on interface %s "
				"that is not on any bridge\n", dev->name);
			break;
		}

		br_num = nss_get_interface_number(nssqdisc_ctx, br);
		br_qdisc = br->qdisc;
		/*
		 * TODO: Properly ensure that the interface and bridge are
		 * shaped by us.
		 */
		if (if_num < 0 || br_num < 0) {
			nssqdisc_info("No action taken since if_num is %d for %s "
					"and br_num is %d for bridge %s\n", if_num,
					dev->name, br_num, br->name);
			break;
		}

		/*
		 * Call attach or detach according as per event type.
		 */
		if (event == NETDEV_BR_JOIN) {
			nssqdisc_info("Instructing interface %s to attach to bridge(%s) "
					"shaping\n", dev->name, br->name);
			nssqdisc_attach_bshaper(br_qdisc, if_num);
		} else if (event == NETDEV_BR_LEAVE) {
			nssqdisc_info("Instructing interface %s to detach from bridge(%s) "
					"shaping\n",dev->name, br->name);
			nssqdisc_detach_bshaper(br_qdisc, if_num);
		}

		break;
	default:
		nssqdisc_info("Received NETDEV_DEFAULT on interface %s\n", dev->name);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block nssqdisc_device_notifier = {
		.notifier_call = nssqdisc_if_event_cb };

/* =========================== NSSFIFO ========================= */

struct nssfifo_sched_data {
	struct nssqdisc_qdisc nq;	/* Common base class for all nss qdiscs */
	u32 limit;			/* Queue length in packets */
					/* TODO: Support for queue length in bytes */
	u8 set_default;			/* Flag to set qdisc as default qdisc for enqueue */
};

static int nssfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	return nssqdisc_enqueue(skb, sch);
}

static struct sk_buff *nssfifo_dequeue(struct Qdisc *sch)
{
	return nssqdisc_dequeue(sch);
}

static unsigned int nssfifo_drop(struct Qdisc *sch)
{
	nssqdisc_info("nssfifo dropping");
	return nssqdisc_drop(sch);
}

static void nssfifo_reset(struct Qdisc *sch)
{
	nssqdisc_info("nssfifo resetting!");
	nssqdisc_reset(sch);
}

static void nssfifo_destroy(struct Qdisc *sch)
{
	/*
	 * Stop the polling of basic stats
	 */
	nssqdisc_stop_basic_stats_polling(sch);

	nssqdisc_destroy(sch);
	nssqdisc_info("nssfifo destroyed");
}

static const struct nla_policy nssfifo_policy[TCA_NSSFIFO_MAX + 1] = {
	[TCA_NSSFIFO_PARMS] = { .len = sizeof(struct tc_nssfifo_qopt) },
};

static int nssfifo_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct nssfifo_sched_data *q;
	struct nlattr *na[TCA_NSSFIFO_MAX + 1];
	struct tc_nssfifo_qopt *qopt;
	int err;
	struct nss_shaper_configure shaper_node_change_param;

	q = qdisc_priv(sch);

	if (opt == NULL) {
		return -EINVAL;
	}

	err = nla_parse_nested(na, TCA_NSSFIFO_MAX, opt, nssfifo_policy);
	if (err < 0)
		return err;

	if (na[TCA_NSSFIFO_PARMS] == NULL)
		return -EINVAL;

	qopt = nla_data(na[TCA_NSSFIFO_PARMS]);

	if (!qopt->limit) {
		nssqdisc_error("%s: limit must be non-zero\n", __func__);
		return -EINVAL;
	}

	q->limit = qopt->limit;

	/*
	 * Required for basic stats display
	 */
	sch->limit = qopt->limit;

	q->set_default = qopt->set_default;
	nssqdisc_info("%s: limit:%u set_default:%u\n", __func__, qopt->limit, qopt->set_default);

	shaper_node_change_param.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
	shaper_node_change_param.mt.shaper_node_config.snc.fifo_param.limit = q->limit;
	shaper_node_change_param.mt.shaper_node_config.snc.fifo_param.drop_mode = NSS_SHAPER_FIFO_DROP_MODE_TAIL;
	if (nssqdisc_configure(sch, &shaper_node_change_param, NSS_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM) < 0)
		return -EINVAL;

	/*
	 * There is nothing we need to do if the qdisc is not
	 * set as default qdisc.
	 */
	if (q->set_default == 0)
		return 0;

	/*
	 * Set this qdisc to be the default qdisc for enqueuing packets.
	 */
	if (nssqdisc_set_default(sch) < 0)
		return -EINVAL;

	nssqdisc_info("%s: nssfifo queue (qos_tag:%u) set as default\n", __func__, q->nq.qos_tag);
	return 0;
}

static int nssfifo_init(struct Qdisc *sch, struct nlattr *opt)
{
	if (opt == NULL)
		return -EINVAL;

	nssqdisc_info("Initializing Fifo - type %d\n", NSS_SHAPER_NODE_TYPE_FIFO);
	nssfifo_reset(sch);

	if (nssqdisc_init(sch, NSS_SHAPER_NODE_TYPE_FIFO) < 0)
		return -EINVAL;

	nssqdisc_info("NSS fifo initialized - handle %x parent %x\n", sch->handle, sch->parent);
	if (nssfifo_change(sch, opt) < 0) {
		nssqdisc_destroy(sch);
		return -EINVAL;
	}

	/*
	 * Start the stats polling timer
	 */
	nssqdisc_start_basic_stats_polling(sch);

	return 0;
}

static int nssfifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nssfifo_sched_data *q;
	struct nlattr *opts = NULL;
	struct tc_nssfifo_qopt opt;

	nssqdisc_info("Nssfifo Dumping!");

	q = qdisc_priv(sch);
	if (q == NULL) {
		return -1;
	}

	opt.limit = q->limit;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL) {
		goto nla_put_failure;
	}
	if (nla_put(skb, TCA_NSSFIFO_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:		
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;
}

static struct sk_buff *nssfifo_peek(struct Qdisc *sch)
{
	nssqdisc_info("Nssfifo Peeking");
	return nssqdisc_peek(sch);
}

static struct Qdisc_ops nsspfifo_qdisc_ops __read_mostly = {
	.id		=	"nsspfifo",
	.priv_size	=	sizeof(struct nssfifo_sched_data),
	.enqueue	=	nssfifo_enqueue,
	.dequeue	=	nssfifo_dequeue,
	.peek		=	nssfifo_peek,
	.drop		=	nssfifo_drop,
	.init		=	nssfifo_init,
	.reset		=	nssfifo_reset,
	.destroy	=	nssfifo_destroy,
	.change		=	nssfifo_change,
	.dump		=	nssfifo_dump,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops nssbfifo_qdisc_ops __read_mostly = {
	.id		=	"nssbfifo",
	.priv_size	=	sizeof(struct nssfifo_sched_data),
	.enqueue	=	nssfifo_enqueue,
	.dequeue	=	nssfifo_dequeue,
	.peek		=	nssfifo_peek,
	.drop		=	nssfifo_drop,
	.init		=	nssfifo_init,
	.reset		=	nssfifo_reset,
	.destroy	=	nssfifo_destroy,
	.change		=	nssfifo_change,
	.dump		=	nssfifo_dump,
	.owner		=	THIS_MODULE,
};

/* =========================== NSSCODEL ========================= */

struct nsscodel_stats {
	u32 peak_queue_delay;		/* Peak delay experienced by a dequeued packet */
	u32 peak_drop_delay;		/* Peak delay experienced by a packet that is dropped */
};

struct nsscodel_sched_data {
	struct nssqdisc_qdisc nq;	/* Common base class for all nss qdiscs */
	u32 target;			/* Acceptable value of queue delay */
	u32 limit;			/* Length of queue */
	u32 interval;			/* Monitoring interval */
	u8 set_default;			/* Flag to set qdisc as default qdisc for enqueue */
	struct nsscodel_stats stats;	/* Contains nsscodel related stats */
};

static int nsscodel_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	return nssqdisc_enqueue(skb, sch);
}

static struct sk_buff *nsscodel_dequeue(struct Qdisc *sch)
{
	return nssqdisc_dequeue(sch);
}

static unsigned int nsscodel_drop(struct Qdisc *sch)
{
	return nssqdisc_drop(sch);
}

static void nsscodel_reset(struct Qdisc *sch)
{
	nssqdisc_info("nsscodel resetting!");
	nssqdisc_reset(sch);
}

static void nsscodel_destroy(struct Qdisc *sch)
{
	/*
	 * Stop the polling of basic stats
	 */
	nssqdisc_stop_basic_stats_polling(sch);
	nssqdisc_destroy(sch);
	nssqdisc_info("nsscodel destroyed");
}

static const struct nla_policy nsscodel_policy[TCA_NSSCODEL_MAX + 1] = {
	[TCA_NSSCODEL_PARMS] = { .len = sizeof(struct tc_nsscodel_qopt) },
};

static int nsscodel_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct nsscodel_sched_data *q;
	struct nlattr *na[TCA_NSSCODEL_MAX + 1];
	struct tc_nsscodel_qopt *qopt;
	struct nss_shaper_configure shaper_node_change_param;
	int err;
	struct net_device *dev = qdisc_dev(sch);

	q = qdisc_priv(sch);

	if (opt == NULL)
		return -EINVAL;

	err = nla_parse_nested(na, TCA_NSSCODEL_MAX, opt, nsscodel_policy);
	if (err < 0)
		return err;

	if (na[TCA_NSSCODEL_PARMS] == NULL)
		return -EINVAL;

	qopt = nla_data(na[TCA_NSSCODEL_PARMS]);

	if (!qopt->target || !qopt->interval || !qopt->limit) {
		nssqdisc_error("nsscodel requires a non-zero value for target, "
				"interval and limit\n");
		return -EINVAL;
	}

	q->target = qopt->target;
	q->limit = qopt->limit;
	q->interval = qopt->interval;
	q->set_default = qopt->set_default;

	/*
	 * Required for basic stats display
	 */
	sch->limit = qopt->limit;

	nssqdisc_info("Target:%u Limit:%u Interval:%u set_default = %u\n",
		q->target, q->limit, q->interval, qopt->set_default);


	shaper_node_change_param.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
	/*
	 * Target and interval time needs to be provided in milliseconds
	 * (tc provides us the time in mircoseconds and therefore we divide by 100)
	 */
	shaper_node_change_param.mt.shaper_node_config.snc.codel_param.qlen_max = q->limit;
	shaper_node_change_param.mt.shaper_node_config.snc.codel_param.cap.interval = q->interval/1000;
	shaper_node_change_param.mt.shaper_node_config.snc.codel_param.cap.target = q->target/1000;
	shaper_node_change_param.mt.shaper_node_config.snc.codel_param.cap.mtu = dev->mtu;
	nssqdisc_info("%s: MTU size of interface %s is %u\n", __func__, dev->name, dev->mtu);

	if (nssqdisc_configure(sch, &shaper_node_change_param,
				NSS_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM) < 0) {
		return -EINVAL;
	}

	/*
	 * There is nothing we need to do if the qdisc is not
	 * set as default qdisc.
	 */
	if (!q->set_default)
		return 0;

	/*
	 * Set this qdisc to be the default qdisc for enqueuing packets.
	 */
	if (nssqdisc_set_default(sch) < 0)
		return -EINVAL;

	return 0;
}

static int nsscodel_init(struct Qdisc *sch, struct nlattr *opt)
{
	if (opt == NULL)
		return -EINVAL;

	nsscodel_reset(sch);
	if (nssqdisc_init(sch, NSS_SHAPER_NODE_TYPE_CODEL) < 0)
		return -EINVAL;

	if (nsscodel_change(sch, opt) < 0) {
		nssqdisc_destroy(sch);
		return -EINVAL;
	}

	/*
	 * Start the stats polling timer
	 */
	nssqdisc_start_basic_stats_polling(sch);

	return 0;
}

static int nsscodel_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nsscodel_sched_data *q;
	struct nlattr *opts = NULL;
	struct tc_nsscodel_qopt opt;

	nssqdisc_info("NssCodel Dumping!");

	q = qdisc_priv(sch);
	if (q == NULL) {
		return -1;
	}

	opt.target = q->target;
	opt.limit = q->limit;
	opt.interval = q->interval;
	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL) {
		goto nla_put_failure;
	}
	if (nla_put(skb, TCA_NSSCODEL_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;
}

static int nsscodel_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct nsscodel_sched_data *q = qdisc_priv(sch);
	struct tc_nsscodel_xstats st = {
		.peak_queue_delay = q->nq.basic_stats_latest.packet_latency_peak_msec_dequeued,
		.peak_drop_delay = q->nq.basic_stats_latest.packet_latency_peak_msec_dropped,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *nsscodel_peek(struct Qdisc *sch)
{
	nssqdisc_info("Nsscodel Peeking");
	return nssqdisc_peek(sch);
}


static struct Qdisc_ops nsscodel_qdisc_ops __read_mostly = {
	.id		=	"nsscodel",
	.priv_size	=	sizeof(struct nsscodel_sched_data),
	.enqueue	=	nsscodel_enqueue,
	.dequeue	=	nsscodel_dequeue,
	.peek		=	nsscodel_peek,
	.drop		=	nsscodel_drop,
	.init		=	nsscodel_init,
	.reset		=	nsscodel_reset,
	.destroy	=	nsscodel_destroy,
	.change		=	nsscodel_change,
	.dump		=	nsscodel_dump,
	.dump_stats	=	nsscodel_dump_stats,
	.owner		=	THIS_MODULE,
};

/* =========================== NSSTBL ========================= */

struct nsstbl_sched_data {
	struct nssqdisc_qdisc nq;	/* Common base class for all nss qdiscs */
	u32 rate;			/* Limiting rate of TBL */
	u32 peakrate;			/* Maximum rate to control bursts */
	u32 burst;			/* Maximum allowed burst size */
	u32 mtu;			/* MTU of the interface attached to */
	u32 mpu;			/* Minimum size of a packet (when there is
					 * no data)
					 */
	struct Qdisc *qdisc;		/* Qdisc to which it is attached to */
};


static int nsstbl_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	return nssqdisc_enqueue(skb, sch);
}

static struct sk_buff *nsstbl_dequeue(struct Qdisc *sch)
{
	return nssqdisc_dequeue(sch);
}

static unsigned int nsstbl_drop(struct Qdisc *sch)
{
	return nssqdisc_drop(sch);
}

static struct sk_buff *nsstbl_peek(struct Qdisc *sch)
{
	return nssqdisc_peek(sch);
}

static void nsstbl_reset(struct Qdisc *sch)
{
	nssqdisc_reset(sch);
}

static void nsstbl_destroy(struct Qdisc *sch)
{
	struct nsstbl_sched_data *q = qdisc_priv(sch);
	qdisc_destroy(q->qdisc);

	/*
	 * Stop the polling of basic stats
	 */
	nssqdisc_start_basic_stats_polling(sch);
	nssqdisc_destroy(sch);
}

static const struct nla_policy nsstbl_policy[TCA_NSSTBL_MAX + 1] = {
	[TCA_NSSTBL_PARMS] = { .len = sizeof(struct tc_nsstbl_qopt) },
};

static int nsstbl_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct nsstbl_sched_data *q;
	struct nlattr *na[TCA_NSSTBL_MAX + 1];
	struct tc_nsstbl_qopt *qopt;
	struct nss_shaper_configure shaper_node_change_param;
	int err;

	q = qdisc_priv(sch);

	if (opt == NULL)
		return -EINVAL;

	err = nla_parse_nested(na, TCA_NSSTBL_MAX, opt, nsstbl_policy);
	if (err < 0)
		return err;

	if (na[TCA_NSSTBL_PARMS] == NULL)
		return -EINVAL;

	qopt = nla_data(na[TCA_NSSTBL_PARMS]);

	/*
	 * Burst size cannot be less than MTU
	 */
	if (qopt->burst < qopt->mtu) {
		nssqdisc_error("Burst size: %u is less than the specified MTU: %u\n", qopt->burst, qopt->mtu);
		return -EINVAL;
	}

	/*
	 * For peak rate to work, MTU must be specified.
	 */
	if (qopt->peakrate > 0 && qopt->mtu == 0) {
		nssqdisc_error("MTU cannot be zero if peakrate is specified\n");
		return -EINVAL;
	}

	
	/*
	 * Rate can be zero. Therefore we dont do a check on it.
	 */
	q->rate = qopt->rate;
	nssqdisc_info("Rate = %u", qopt->rate);
	q->burst = qopt->burst;
	nssqdisc_info("Burst = %u", qopt->burst);
	q->mtu = qopt->mtu;
	nssqdisc_info("MTU = %u", qopt->mtu);
	q->peakrate = qopt->peakrate;
	nssqdisc_info("Peak Rate = %u", qopt->peakrate);

	shaper_node_change_param.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_cir.rate = q->rate;
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_cir.burst = q->burst;
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_cir.max_size = q->mtu;
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit = false;
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_pir.rate = q->peakrate;

	/*
	 * It is important to set these two parameters to be the same as MTU.
	 * This ensures bursts from CIR dont go above the specified peakrate.
	 */
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_pir.burst = q->mtu;
	shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_pir.max_size = q->mtu;

	if (q->peakrate) {
		shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit = false;
	} else {
		shaper_node_change_param.mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit = true;
	}

	if (nssqdisc_configure(sch, &shaper_node_change_param,
			NSS_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM) < 0) {
		return -EINVAL;
	}

	return 0;
}

static int nsstbl_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct nsstbl_sched_data *q = qdisc_priv(sch);

	if (opt == NULL)
		return -EINVAL;

	q->qdisc = &noop_qdisc;

	if (nssqdisc_init(sch, NSS_SHAPER_NODE_TYPE_TBL) < 0)
		return -EINVAL;

	if (nsstbl_change(sch, opt) < 0) {
		nssqdisc_info("Failed to configure tbl\n");
		nssqdisc_destroy(sch);
		return -EINVAL;
	}

	/*
	 * Start the stats polling timer
	 */
	nssqdisc_start_basic_stats_polling(sch);

	return 0;
}

static int nsstbl_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nsstbl_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;
	struct tc_nsstbl_qopt opt = {
		.rate		= q->rate,
		.peakrate	= q->peakrate,
		.burst		= q->burst,
		.mtu		= q->mtu,
	};

	nssqdisc_info("Nsstbl dumping");
	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	NLA_PUT(skb, TCA_NSSTBL_PARMS, sizeof(opt), &opt);
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;	
}

static int nsstbl_dump_class(struct Qdisc *sch, unsigned long cl,
			     struct sk_buff *skb, struct tcmsg *tcm)
{
	struct nsstbl_sched_data *q = qdisc_priv(sch);
	nssqdisc_info("Nsstbl dumping class");

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;

	return 0;
}

static int nsstbl_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
			struct Qdisc **old)
{
	struct nsstbl_sched_data *q = qdisc_priv(sch);
	struct nssqdisc_qdisc *nq_new = (struct nssqdisc_qdisc *)qdisc_priv(new);
	struct nss_shaper_configure shaper_node_attach, shaper_node_detach;

	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = q->qdisc;
	q->qdisc = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	nssqdisc_info("%s:Grafting old: %p with new: %p\n", __func__, *old, new);
	if (*old != &noop_qdisc) {
		nssqdisc_info("%s: Detaching old: %p\n", __func__, *old);
		shaper_node_detach.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
		if (nssqdisc_node_detach(sch, &shaper_node_detach,
				NSS_SHAPER_CONFIG_TYPE_TBL_DETACH) < 0) {
			return -EINVAL;
		}
	}

	if (new != &noop_qdisc) {
		nssqdisc_info("%s: Attaching new: %p\n", __func__, new);
		shaper_node_attach.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
		shaper_node_attach.mt.shaper_node_config.snc.tbl_attach.child_qos_tag = nq_new->qos_tag;
		if (nssqdisc_node_attach(sch, &shaper_node_attach,
				NSS_SHAPER_CONFIG_TYPE_TBL_ATTACH) < 0) {
			return -EINVAL;
		}
	}

	nssqdisc_info("Nsstbl grafted");

	return 0;
}

static struct Qdisc *nsstbl_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct nsstbl_sched_data *q = qdisc_priv(sch);
	nssqdisc_info("Nsstbl returns leaf");
	return q->qdisc;
}

static unsigned long nsstbl_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void nsstbl_put(struct Qdisc *sch, unsigned long arg)
{
}

static void nsstbl_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	nssqdisc_info("Nsstbl walk called");
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops nsstbl_class_ops = {
	.graft		=	nsstbl_graft,
	.leaf		=	nsstbl_leaf,
	.get		=	nsstbl_get,
	.put		=	nsstbl_put,
	.walk		=	nsstbl_walk,
	.dump		=	nsstbl_dump_class,
};

static struct Qdisc_ops nsstbl_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.id		=	"nsstbl",
	.priv_size	=	sizeof(struct nsstbl_sched_data),
	.cl_ops		=	&nsstbl_class_ops,
	.enqueue	=	nsstbl_enqueue,
	.dequeue	=	nsstbl_dequeue,
	.peek		=	nsstbl_peek,
	.drop		=	nsstbl_drop,
	.init		=	nsstbl_init,
	.reset		=	nsstbl_reset,
	.destroy	=	nsstbl_destroy,
	.change		=	nsstbl_change,
	.dump		=	nsstbl_dump,
	.owner		=	THIS_MODULE,
};

/* =========================== NSSPRIO ========================= */

struct nssprio_sched_data {
	struct nssqdisc_qdisc nq;	/* Common base class for all nss qdiscs */
	int bands;			/* Number of priority bands to use */
	struct Qdisc *queues[TCA_NSSPRIO_MAX_BANDS];
					/* Array of child qdisc holder */
};

static int nssprio_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	return nssqdisc_enqueue(skb, sch);
}

static struct sk_buff *nssprio_dequeue(struct Qdisc *sch)
{
	return nssqdisc_dequeue(sch);
}

static unsigned int nssprio_drop(struct Qdisc *sch)
{
	return nssqdisc_drop(sch);
}

static struct sk_buff *nssprio_peek(struct Qdisc *sch)
{
	return nssqdisc_peek(sch);
}

static void nssprio_reset(struct Qdisc *sch)
{
	return nssqdisc_reset(sch);
}

static void nssprio_destroy(struct Qdisc *sch)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	int i;

	nssqdisc_info("Destroying prio");

	/*
	 * Destroy all attached child nodes before destroying prio
	 */
	for (i = 0; i < q->bands; i++)
		qdisc_destroy(q->queues[i]);

	/*
	 * Stop the polling of basic stats
	 */
	nssqdisc_stop_basic_stats_polling(sch);

	nssqdisc_destroy(sch);
}

static const struct nla_policy nssprio_policy[TCA_NSSTBL_MAX + 1] = {
	[TCA_NSSTBL_PARMS] = { .len = sizeof(struct tc_nssprio_qopt) },
};

static int nssprio_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct nssprio_sched_data *q;
	struct nlattr *na[TCA_NSSTBL_MAX + 1];
	struct tc_nssprio_qopt *qopt;
	int err;

	q = qdisc_priv(sch);

	if (opt == NULL) {
		return -EINVAL;
	}

	err = nla_parse_nested(na, TCA_NSSPRIO_MAX, opt, nssprio_policy);
	if (err < 0) {
		return err;
	}

	if (na[TCA_NSSPRIO_PARMS] == NULL) {
		return -EINVAL;
	}

	qopt = nla_data(na[TCA_NSSPRIO_PARMS]);

	if (qopt->bands > TCA_NSSPRIO_MAX_BANDS) {
		return -EINVAL;
	}

	q->bands = qopt->bands;
	nssqdisc_info("Bands = %u\n", qopt->bands);

	return 0;
}

static int nssprio_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	int i;

	if (opt == NULL)
		return -EINVAL;

	for (i = 0; i < TCA_NSSPRIO_MAX_BANDS; i++)
		q->queues[i] = &noop_qdisc;

	q->bands = 0;
	if (nssqdisc_init(sch, NSS_SHAPER_NODE_TYPE_PRIO) < 0)
		return -EINVAL;

	nssqdisc_info("Nssprio initialized - handle %x parent %x\n",
			sch->handle, sch->parent);
	if (nssprio_change(sch, opt) < 0) {
		nssqdisc_destroy(sch);
		return -EINVAL;
	}

	/*
	 * Start the stats polling timer
	 */
	nssqdisc_start_basic_stats_polling(sch);
	return 0;
}

static int nssprio_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;
	struct tc_nssprio_qopt qopt; 

	nssqdisc_info("Nssprio dumping");
	qopt.bands = q->bands;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	NLA_PUT(skb, TCA_NSSPRIO_PARMS, sizeof(qopt), &qopt);
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;	
}

static int nssprio_graft(struct Qdisc *sch, unsigned long arg,
				struct Qdisc *new, struct Qdisc **old)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	struct nssqdisc_qdisc *nq_new = (struct nssqdisc_qdisc *)qdisc_priv(new);
	uint32_t band = (uint32_t)(arg - 1);
	struct nss_shaper_configure shaper_node_attach, shaper_node_detach;

	nssqdisc_info("Grafting band %u, available bands %u\n", band, q->bands);

	if (new == NULL)
		new = &noop_qdisc;

	if (band > q->bands)
		return -EINVAL;

	sch_tree_lock(sch);
	*old = q->queues[band];
	q->queues[band] = new;
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	nssqdisc_info("%s:Grafting old: %p with new: %p\n", __func__, *old, new);
	if (*old != &noop_qdisc) {
		nssqdisc_info("%s:Detaching old: %p\n", __func__, *old);
		shaper_node_detach.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
		shaper_node_detach.mt.shaper_node_config.snc.prio_detach.priority = band;
		if (nssqdisc_node_detach(sch, &shaper_node_detach,
				NSS_SHAPER_CONFIG_TYPE_PRIO_DETACH) < 0) {
			return -EINVAL;
		}
	}

	if (new != &noop_qdisc) {
		nssqdisc_info("%s:Attaching new child with qos tag: %x, priority: %u to "
				"qos_tag: %x\n", __func__, nq_new->qos_tag, band, q->nq.qos_tag);
		shaper_node_attach.mt.shaper_node_config.qos_tag = q->nq.qos_tag;
		shaper_node_attach.mt.shaper_node_config.snc.prio_attach.child_qos_tag = nq_new->qos_tag;
		shaper_node_attach.mt.shaper_node_config.snc.prio_attach.priority = band;
		if (nssqdisc_node_attach(sch, &shaper_node_attach,
				NSS_SHAPER_CONFIG_TYPE_PRIO_ATTACH) < 0) {
			return -EINVAL;
		}
	}
	nssqdisc_info("Nssprio grafted");

	return 0;
}

static struct Qdisc *nssprio_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	uint32_t band = (uint32_t)(arg - 1);

	nssqdisc_info("Nssprio returns leaf");

	if (band > q->bands)
		return NULL;

	return q->queues[band];
}

static unsigned long nssprio_get(struct Qdisc *sch, u32 classid)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	unsigned long band = TC_H_MIN(classid);

	nssqdisc_info("Inside get. Handle - %x Classid - %x Band %lu Available band %u", sch->handle, classid, band, q->bands);

	if (band > q->bands)
		return 0;

	return band;
}

static void nssprio_put(struct Qdisc *sch, unsigned long arg)
{
	nssqdisc_info("Inside prio get\n");
}

static void nssprio_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	int i;

	if (arg->stop)
		return;

	for (i = 0; i < q->bands; i++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, i + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
	nssqdisc_info("Nssprio walk called");
}

static int nssprio_dump_class(struct Qdisc *sch, unsigned long cl,
			     struct sk_buff *skb, struct tcmsg *tcm)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = q->queues[cl - 1]->handle;

	nssqdisc_info("Nssprio dumping class");
	return 0;
}

static int nssprio_dump_class_stats(struct Qdisc *sch, unsigned long cl,
			     	    struct gnet_dump *d)
{
	struct nssprio_sched_data *q = qdisc_priv(sch);
	struct Qdisc *cl_q;

	cl_q = q->queues[cl - 1];
	cl_q->qstats.qlen = cl_q->q.qlen;
	if (gnet_stats_copy_basic(d, &cl_q->bstats) < 0 ||
	    gnet_stats_copy_queue(d, &cl_q->qstats) < 0)
		return -1;

	nssqdisc_info("Nssprio dumping class stats");
	return 0;
}

static const struct Qdisc_class_ops nssprio_class_ops = {
	.graft		=	nssprio_graft,
	.leaf		=	nssprio_leaf,
	.get		=	nssprio_get,
	.put		=	nssprio_put,
	.walk		=	nssprio_walk,
	.dump		=	nssprio_dump_class,
	.dump_stats	=	nssprio_dump_class_stats,
};

static struct Qdisc_ops nssprio_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.id		=	"nssprio",
	.priv_size	=	sizeof(struct nssprio_sched_data),
	.cl_ops		=	&nssprio_class_ops,
	.enqueue	=	nssprio_enqueue,
	.dequeue	=	nssprio_dequeue,
	.peek		=	nssprio_peek,
	.drop		=	nssprio_drop,
	.init		=	nssprio_init,
	.reset		=	nssprio_reset,
	.destroy	=	nssprio_destroy,
	.change		=	nssprio_change,
	.dump		=	nssprio_dump,
	.owner		=	THIS_MODULE,
};

/* ================== Module registration ================= */

static int __init nssqdisc_module_init(void)
{
	int ret;
	nssqdisc_info("Module initializing");
	nssqdisc_ctx = nss_register_shaping();

	ret = register_qdisc(&nsspfifo_qdisc_ops);
	if (ret != 0)
		return ret;
	nssqdisc_info("NSS pfifo registered");

	ret = register_qdisc(&nssbfifo_qdisc_ops);
	if (ret != 0)
		return ret;
	nssqdisc_info("NSS bfifo registered");

	ret = register_qdisc(&nsscodel_qdisc_ops);
	if (ret != 0)
		return ret;
	nssqdisc_info("NSSCodel registered");

	ret = register_qdisc(&nsstbl_qdisc_ops);
	if (ret != 0)
		return ret;
	nssqdisc_info("NSSTBL registered");

	ret = register_qdisc(&nssprio_qdisc_ops);
	if (ret != 0)
		return ret;
	nssqdisc_info("NSSPRIO registered");

	ret = register_netdevice_notifier(&nssqdisc_device_notifier);
	if (ret != 0)
		return ret;
 	nssqdisc_info("NSS qdisc device notifiers registered");

	return 0;
}

static void __exit nssqdisc_module_exit(void)
{
	unregister_qdisc(&nsspfifo_qdisc_ops);
	nssqdisc_info("NSSPFIFO Unregistered");
	unregister_qdisc(&nssbfifo_qdisc_ops);
	nssqdisc_info("NSSBFIFO Unregistered");
	unregister_qdisc(&nsscodel_qdisc_ops);
	nssqdisc_info("NSSCODEL Unregistered");
	unregister_qdisc(&nsstbl_qdisc_ops);
	nssqdisc_info("NSSTBL Unregistered");
	unregister_qdisc(&nssprio_qdisc_ops);
	nssqdisc_info("NSSPRIO Unregistered");
	unregister_netdevice_notifier(&nssqdisc_device_notifier);
}

module_init(nssqdisc_module_init)
module_exit(nssqdisc_module_exit)

MODULE_LICENSE("GPL");
