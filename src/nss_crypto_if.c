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
#include <nss_crypto_hlos.h>
#include <nss_crypto_if.h>
#include <nss_crypto_hw.h>
#include <nss_crypto_ctrl.h>
#include <nss_api_if.h>

/*
 * global control component
 */
extern struct nss_crypto_ctrl gbl_crypto_ctrl;

void *nss_drv_hdl;
void *nss_pm_hdl;

/*
 * internal structure for a buffer node
 */
struct nss_crypto_buf_node {
	struct llist_node node;			/* lockless node */
	struct nss_crypto_buf buf;		/* crypto buffer */
};

/*
 * users of crypto driver
 */
struct nss_crypto_user {
	struct list_head  node;			/* user list */
	struct llist_head pool_head;	/* buffer pool lockless list */

	nss_crypto_user_ctx_t ctx;		/* user specific context*/

	nss_crypto_attach_t attach;		/* attach function*/
	nss_crypto_detach_t detach;		/* detach function*/

	struct kmem_cache *zone;
};

LIST_HEAD(user_head);

/*
 * XXX: its expected that this should be sufficient for 4 pipes
 */
static uint32_t pool_seed = 1024;

/*
 * nss_crypto_register_user()
 * 	register a new user of the crypto driver
 */
void nss_crypto_register_user(nss_crypto_attach_t attach, nss_crypto_detach_t detach)
{
	struct nss_crypto_user *user;
	struct nss_crypto_buf_node *entry;
	int i;

	user = vmalloc(sizeof(struct nss_crypto_user));
	nss_crypto_assert(user);

	memset(user, 0, sizeof(struct nss_crypto_user));

	user->attach = attach;
	user->ctx = user->attach(user);
	user->detach = detach;

	/*
	 * initialize the lockless list
	 */
	init_llist_head(&user->pool_head);

	/*
	 * Allocated the kmem_cache pool of crypto_bufs
	 * XXX: we can use the constructor
	 */
	user->zone = kmem_cache_create("crypto_buf", sizeof(struct nss_crypto_buf_node), 0, SLAB_HWCACHE_ALIGN, NULL);

	for (i = 0; i < pool_seed; i++) {
		entry = kmem_cache_alloc(user->zone, GFP_KERNEL);
		llist_add(&entry->node, &user->pool_head);
	}

	list_add_tail(&user->node, &user_head);
}
EXPORT_SYMBOL(nss_crypto_register_user);

/*
 * nss_crypto_unregister_user()
 * 	unregister a user from the crypto driver
 */
void nss_crypto_unregister_user(nss_crypto_handle_t crypto)
{
	struct nss_crypto_user *user;
	struct nss_crypto_buf_node *entry;
	struct llist_node *node;
	uint32_t buf_count;

	user = (struct nss_crypto_user *)crypto;
	buf_count = 0;

	/*
	 * XXX: need to handle the case when there are packets in flight
	 * for the user
	 */
	if (user->detach) {
		user->detach(user->ctx);
	}

	while (!llist_empty(&user->pool_head)) {
		buf_count++;

		node = llist_del_first(&user->pool_head);
		entry = container_of(node, struct nss_crypto_buf_node, node);

		kmem_cache_free(user->zone, entry);
	}

	/*
	 * it will assert for now if some buffers where in flight while the deregister
	 * happened
	 */
	nss_crypto_assert(buf_count >= pool_seed);

	kmem_cache_destroy(user->zone);

	list_del(&user->node);

	vfree(user);
}
EXPORT_SYMBOL(nss_crypto_unregister_user);

/*
 * nss_crypto_buf_alloc()
 * 	allocate a crypto buffer for its user
 *
 * the allocation happens from its user pool. If, a user runs out its pool
 * then it will only be affected. Also, this function is lockless
 */
struct nss_crypto_buf *nss_crypto_buf_alloc(nss_crypto_handle_t hdl)
{
	struct nss_crypto_user *user;
	struct nss_crypto_buf_node *entry;
	struct llist_node *node;

	user = (struct nss_crypto_user *)hdl;
	node = llist_del_first(&user->pool_head);

	if (node) {
		entry = container_of(node, struct nss_crypto_buf_node, node);
		return &entry->buf;
	}

	/*
	 * Note: this condition is hit when there are more than 'seed' worth
	 * of crypto buffers outstanding with the system. Instead of failing
	 * allocation attempt allocating buffers so that pool grows itself
	 * to the right amount needed to sustain the traffic without the need
	 * for dynamic allocation in future requests
	 */
	entry = kmem_cache_alloc(user->zone, GFP_KERNEL);

	return &entry->buf;
}
EXPORT_SYMBOL(nss_crypto_buf_alloc);

/*
 * nss_crypto_buf_free()
 * 	free the crypto buffer back to the user buf pool
 */
void nss_crypto_buf_free(nss_crypto_handle_t hdl, struct nss_crypto_buf *buf)
{
	struct nss_crypto_user *user;
	struct nss_crypto_buf_node *entry;

	user = (struct nss_crypto_user *)hdl;

	entry = container_of(buf, struct nss_crypto_buf_node, buf);

	llist_add(&entry->node, &user->pool_head);

}
EXPORT_SYMBOL(nss_crypto_buf_free);

/*
 * nss_crypto_transform_done()
 * 	completion callback for NSS HLOS driver when it receives a crypto buffer
 *
 * this function assumes packets arriving from host are transform buffers that
 * have been completed by the NSS crypto. It needs to have a switch case for
 * detecting control packets also
 */
void nss_crypto_transform_done(void *ctx, void *buffer, uint32_t paddr, uint16_t len)
{
	struct nss_crypto_buf *buf = (struct nss_crypto_buf *)buffer;

	dma_unmap_single(NULL, paddr, sizeof(struct nss_crypto_buf), DMA_FROM_DEVICE);
	dma_unmap_single(NULL, buf->data_paddr, buf->data_len + buf->hash_len, DMA_FROM_DEVICE);

	buf->cb_fn(buf);
}

/*
 * nss_crypto_transform_payload()
 *	submit a transform for crypto operation to NSS
 */
nss_crypto_status_t nss_crypto_transform_payload(nss_crypto_handle_t crypto, struct nss_crypto_buf *buf)
{
	struct nss_crypto_ctrl *ctrl = &gbl_crypto_ctrl;
	nss_tx_status_t nss_status;
	uint32_t paddr;

	if (!nss_crypto_check_idx_state(ctrl->idx_state_bitmap, buf->session_idx)) {
		nss_crypto_session_update(ctrl, buf);
		nss_crypto_set_idx_state(&ctrl->idx_state_bitmap, buf->session_idx);
	}

	buf->data_paddr = dma_map_single(NULL, buf->data, buf->data_len, DMA_TO_DEVICE);
	paddr = dma_map_single(NULL, buf, sizeof(struct nss_crypto_buf), DMA_TO_DEVICE);

	nss_status = nss_tx_crypto_if_buf(nss_drv_hdl, buf, paddr, sizeof(struct nss_crypto_buf));

	return (nss_status == NSS_TX_FAILURE) ? NSS_CRYPTO_STATUS_FAIL : NSS_CRYPTO_STATUS_OK;
}
EXPORT_SYMBOL(nss_crypto_transform_payload);

/*
 * nss_crypto_init()
 * 	initialize the crypto driver
 *
 * this will do the following
 * - Bring Power management perf level to TURBO
 * - register itself to the NSS HLOS driver
 * - wait for the NSS to be ready
 * - initialize the control component
 */
void nss_crypto_init(void)
{
	nss_pm_interface_status_t status;

	nss_crypto_info("Waiting for NSS \n");

	nss_drv_hdl = nss_register_crypto_if(nss_crypto_transform_done, &user_head);

	while(nss_get_state(nss_drv_hdl) != NSS_STATE_INITIALIZED) {
		nss_crypto_info(".");
	}
	nss_crypto_info(" done!\n");

	nss_crypto_ctrl_init();

	nss_pm_hdl = nss_pm_client_register(NSS_PM_CLIENT_CRYPTO);

	status = nss_pm_set_perf_level(nss_pm_hdl, NSS_PM_PERF_LEVEL_TURBO);
	if (status == NSS_PM_API_FAILED) {
		nss_crypto_info(" Not able to set pm perf level to TURBO!!!\n");
	}
}

/*
 * nss_crypto_engine_init()
 * 	initialize the crypto interface for each engine
 *
 * this will do the following
 * - prepare the open message for the engine
 * - initialize the control component for all pipes in that engine
 * - send the open message to the NSS crypto
 */
void nss_crypto_engine_init(uint32_t eng_count)
{
	struct nss_crypto_open_eng open;
	struct nss_crypto_ctrl_eng *e_ctrl;
	int i;

	e_ctrl = &gbl_crypto_ctrl.eng[eng_count];

	/*
	 * prepare the open message
	 */
	open.eng_id = eng_count;
	open.bam_pbase = e_ctrl->bam_pbase;

	for (i = 0; i < NSS_CRYPTO_BAM_PP; i++) {
		nss_crypto_pipe_init(e_ctrl, i, &open.desc_paddr[i], &e_ctrl->hw_desc[i]);
	}

	if (nss_crypto_idx_init(e_ctrl, open.idx) != NSS_CRYPTO_STATUS_OK) {
		nss_crypto_err("failed to initiallize\n");
		return;
	}

	/*
	 * send open message to NSS crypto
	 */
	nss_tx_crypto_if_open(nss_drv_hdl, (uint8_t *)&open, sizeof(struct nss_crypto_open_eng));
}



