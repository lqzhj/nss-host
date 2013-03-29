/* * Copyright (c) 2013 Qualcomm Atheros, Inc. * */

/*
 * na_core.c
 *	NSS driver core APIs source file.
 */

#include "nss_core.h"
#include <nss_hal.h>
#include <asm/barrier.h>

/*
 * nss_send_c2c_map()
 *	Send C2C map to NSS
 */
static int32_t nss_send_c2c_map(struct nss_ctx_instance *nss_own, struct nss_ctx_instance *nss_other)
{
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_c2c_tx_map *nctm;

	nss_info("%p: C2C map:%x\n", nss_own, nss_other->c2c_start);

	nbuf =  __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_own->nss_top->stats_lock);
		nss_own->nss_top->nbuf_alloc_err++;
		spin_unlock_bh(&nss_own->nss_top->stats_lock);
		return NSS_CORE_STATUS_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_C2C_TX_MAP;

	nctm = &ntmo->sub.c2c_tx_map;
	nctm->c2c_start = nss_other->c2c_start;
	nctm->c2c_int_addr = (uint32_t)(nss_other->nphys) + NSS_REGS_C2C_INTR_SET_OFFSET;

	status = nss_core_send_buffer(nss_own, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'c2c tx map' - marked as stopped\n", nss_own);
		return NSS_CORE_STATUS_FAILURE;
	}

	nss_hal_send_interrupt(nss_own->nmap, nss_own->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_CORE_STATUS_SUCCESS;
}

/*
 * nss_core_cause_to_queue()
 *     Map interrupt cause to queue id
 */
static inline uint16_t nss_core_cause_to_queue (uint16_t cause)
{
	uint16_t qid = 0;

	if (likely(cause == NSS_REGS_N2H_INTR_STATUS_DATA_COMMAND_QUEUE)) {
		qid = NSS_IF_DATA_QUEUE;
	} else if (cause == NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFER_QUEUE) {
		qid = NSS_IF_EMPTY_BUFFER_QUEUE;
	} else {
		/*
		 * There is no way we can reach here as cause was already identified as a queue cause
		 */
		nss_assert(0);
	}

	return qid;
}

/*
 * nss_core_handle_cause_queue()
 *	Handle interrupt cause related to N2H/H2N queues
 */
static int32_t nss_core_handle_cause_queue(struct nss_ctx_instance *nss_ctx, uint16_t cause, int16_t weight)
{
	int16_t count, count_temp;
	uint16_t size, mask, qid;
	uint32_t nss_index, hlos_index;
	struct sk_buff *nbuf;
	struct n2h_desc_if_instance *desc_if;
	struct n2h_descriptor *desc;
	struct nss_if_mem_map *if_map = (struct nss_if_mem_map *)(nss_ctx->vmap);

	qid = nss_core_cause_to_queue(cause);

	/*
	 * Make sure qid < num_rings
	 */
	nss_assert(qid < if_map->n2h_rings);

	desc_if = &nss_ctx->n2h_desc_if[qid];
	nss_index = if_map->n2h_nss_index[qid];
	hlos_index = if_map->n2h_hlos_index[qid];
	size = desc_if->size;
	mask = size - 1;

	/*
	 * Check if there is work to be done for this queue
	 */
	count = ((nss_index - hlos_index) + size) & (mask);

	if (likely(count != 0)) {
		/*
		 * Restrict ourselves to suggested weight
		 */
		if (count > weight) {
			count = weight;
		}

		count_temp = count;

	} else {
		return 0;
	}

	while (count_temp) {
		desc = &(desc_if->desc[hlos_index]);

		if (unlikely((desc->buffer_type == N2H_BUFFER_CRYPTO_RESP))) {
			/* This is a crypto buffer hence send it to crypto driver */
			nss_rx_handle_crypto_buf(nss_ctx, desc->opaque, desc->buffer, desc->payload_len);
		} else {
			/*
			* Obtain the nbuf
			*/
			nbuf = (struct sk_buff *)desc->opaque;

			/*
			 * Set relevant fields within nbuf (len, head, tail)
			 */
			nbuf->data = nbuf->head + desc->payload_offs;
			nbuf->len = desc->payload_len;
			nbuf->tail = nbuf->data + nbuf->len;

			/*
			 * TODO: Unmap data buffer area for scatter-gather
			 * TODO: Check if there is any issue wrt map and unmap, NSS should playaround with data area and should not
			 *	touch HEADROOM area
			 */
			dma_unmap_single(NULL, (desc->buffer + desc->payload_offs), desc->payload_len, DMA_FROM_DEVICE);

			switch (desc->buffer_type) {
			case N2H_BUFFER_PACKET:
				/*
				 * Check if NSS was able to obtain checksum
				 */
				nbuf->ip_summed = CHECKSUM_UNNECESSARY;
				if (unlikely(!(desc->bit_flags & N2H_BIT_FLAG_IP_TRANSPORT_CHECKSUM_VALID))) {
					nbuf->ip_summed = CHECKSUM_NONE;
				}

				/*
				 * TODO: Differentiate between physical and virtual interfaces
				 */
				if (likely(nss_ctx->nss_top->phys_if_rx_callback[desc->interface_num])) {
					nss_ctx->nss_top->phys_if_rx_callback[desc->interface_num](
						nss_ctx->nss_top->phys_if_ctx[desc->interface_num], (void *)nbuf);
				} else {
					dev_kfree_skb_any(nbuf);
				}
				break;

			case N2H_BUFFER_STATUS:
				nss_rx_handle_status_pkt(nss_ctx, nbuf);

				/* Fall Through */

			case N2H_BUFFER_EMPTY:
				dev_kfree_skb_any(nbuf);
				break;

			default:
				/*
				 * ERROR:
				 */
				nss_info("%p: Invalid buffer type %d received from NSS", nss_ctx, desc->buffer_type);
			}
		}

		hlos_index = (hlos_index + 1) & (mask);
		count_temp--;
	}

	if_map->n2h_hlos_index[qid] = hlos_index;

	return count;
}

/*
 * nss_core_init_nss()
 *	Initialize NSS core state
 */
static void nss_core_init_nss(struct nss_ctx_instance *nss_ctx, struct nss_if_mem_map *if_map)
{
	int32_t i;

	/*
	 * NOTE: A commonly found error is that sizes and start address of per core
	 *	virtual register map do not match in NSS and HLOS builds. This will lead
	 *	to some hard to trace issues such as spinlock magic check failure etc.
	 *	Following checks will verify that proper virtual map has been initialized
	 */
	nss_assert(if_map->magic == DEV_MAGIC);
	nss_assert(if_map->magic == DEV_MAGIC);

	/*
	 * Copy ring addresses to cacheable locations.
	 * We do not wish to read ring start address through NC accesses
	 */
	for (i = 0; i < if_map->n2h_rings; i++) {
		nss_ctx->n2h_desc_if[i].desc =
			(struct n2h_descriptor *)((uint32_t)if_map->n2h_desc_if[i].desc - (uint32_t)nss_ctx->vphys + (uint32_t)nss_ctx->vmap);
		nss_ctx->n2h_desc_if[i].size = if_map->n2h_desc_if[i].size;
		nss_ctx->n2h_desc_if[i].int_bit = if_map->n2h_desc_if[i].int_bit;
	}

	for (i = 0; i < if_map->h2n_rings; i++) {
		nss_ctx->h2n_desc_rings[i].desc_ring.desc =
			(struct h2n_descriptor *)((uint32_t)if_map->h2n_desc_if[i].desc - (uint32_t)nss_ctx->vphys + (uint32_t)nss_ctx->vmap);
		nss_ctx->h2n_desc_rings[i].desc_ring.size = if_map->h2n_desc_if[i].size;
		nss_ctx->h2n_desc_rings[i].desc_ring.int_bit = if_map->h2n_desc_if[i].int_bit;
		spin_lock_init(&(nss_ctx->h2n_desc_rings[i].lock));
	}

	nss_ctx->c2c_start = if_map->c2c_start;

	spin_lock_bh(&nss_ctx->nss_top->lock);
	nss_ctx->state = NSS_CORE_STATE_INITIALIZED;
	spin_unlock_bh(&nss_ctx->nss_top->lock);
}

/*
 * nss_core_handle_cause_nonqueue()
 *	Handle non-queue interrupt causes (e.g. empty buffer SOS, Tx unblocked)
 *
 */
static int32_t nss_core_handle_cause_nonqueue (struct nss_ctx_instance *nss_ctx, uint32_t cause, int16_t weight)
{
	struct nss_if_mem_map *if_map = (struct nss_if_mem_map *)(nss_ctx->vmap);
	int32_t i;

	/*
	 * TODO: find better mechanism to handle empty buffers
	 */
	if (likely(cause == NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFERS_SOS)) {
		struct sk_buff *nbuf;
		uint16_t count, size;
		int32_t nss_index, hlos_index;
		struct h2n_desc_if_instance *desc_if = &(nss_ctx->h2n_desc_rings[NSS_IF_EMPTY_BUFFER_QUEUE].desc_ring);

		if (unlikely(nss_ctx->state == NSS_CORE_STATE_UNINITIALIZED)) {
			nss_core_init_nss(nss_ctx, if_map);

			for (i = 0; i < NSS_MAX_CORES; i++) {
				if(&nss_ctx->nss_top->nss[i] != nss_ctx) {
					spin_lock_bh(&nss_ctx->nss_top->lock);
					if(nss_ctx->nss_top->nss[i].state == NSS_CORE_STATE_INITIALIZED) {
						spin_unlock_bh(&nss_ctx->nss_top->lock);
						nss_send_c2c_map(&nss_ctx->nss_top->nss[i], nss_ctx);
						nss_send_c2c_map(nss_ctx, &nss_ctx->nss_top->nss[i]);
						continue;
					}
					spin_unlock_bh(&nss_ctx->nss_top->lock);
				}
			}
		}

		/*
		 * Check how many empty buffers could be filled in queue
		 */
		nss_index = if_map->h2n_nss_index[NSS_IF_EMPTY_BUFFER_QUEUE];
		hlos_index = if_map->h2n_hlos_index[NSS_IF_EMPTY_BUFFER_QUEUE];
		size = nss_ctx->h2n_desc_rings[NSS_IF_EMPTY_BUFFER_QUEUE].desc_ring.size;
		count = ((nss_index - hlos_index - 1) + size) & (size - 1);

		nss_info("%p: Adding %d buffers to empty queue", nss_ctx, count);

		/*
		 * Fill empty buffer queue with buffers leaving one empty descriptor
		 * Note that total number of descriptors in queue cannot be more than (size - 1)
		 */
		while (count) {
			struct h2n_descriptor *desc = &(desc_if->desc[hlos_index]);

			nbuf = __dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE, GFP_ATOMIC | __GFP_NOWARN);
			if (unlikely(!nbuf)) {
				/*
				 * ERR:
				 */
				spin_lock_bh(&nss_ctx->nss_top->stats_lock);
				nss_ctx->nss_top->nbuf_alloc_err++;
				spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
				nss_warning("%p: Could not obtain empty buffer", nss_ctx);
				break;
			}

			desc->opaque = (uint32_t)nbuf;
			desc->payload_offs = (uint16_t) (nbuf->data - nbuf->head);
			desc->buffer = dma_map_single(NULL, nbuf->head, (nbuf->end - nbuf->head), DMA_FROM_DEVICE);
			if (unlikely(dma_mapping_error(NULL, desc->buffer))) {
				/*
				 * ERR:
				 */
				dev_kfree_skb_any(nbuf);
				nss_warning("%p: DMA mapping failed for empty buffer", nss_ctx);
				break;
			}
			desc->buffer_len = (uint16_t)(nbuf->end - nbuf->head);
			desc->buffer_type = H2N_BUFFER_EMPTY;
			hlos_index = (hlos_index + 1) & (size - 1);
			count--;
		}

		if_map->h2n_hlos_index[NSS_IF_EMPTY_BUFFER_QUEUE] = hlos_index;

		/*
		 * Inform NSS that new buffers are available
		 */
		nss_hal_send_interrupt(nss_ctx->nmap, desc_if->int_bit, NSS_REGS_H2N_INTR_STATUS_EMPTY_BUFFER_QUEUE);
	} else if (cause == NSS_REGS_N2H_INTR_STATUS_TX_UNBLOCKED) {
		/*
		 * TODO: kick off transmit queue again
		 */

		/*
		 * TODO: Mask Tx unblocked interrupt and unmask it when we get in to queue full condition again
		 */
		nss_warning("%p: Tx Unblocked is not supported in this version of driver", nss_ctx);
	} else {
		/*
		 * There is no way we can reach here as we already identified this cause
		 * as non-queue cause
		 */
		nss_assert(0);
	}

	return 0;
}

/*
 * nss_core_get_prioritized_cause()
 *	Obtain proritized cause (from multiple interrupt causes) that
 *	must be handled by NSS driver first
 */
static uint32_t nss_core_get_prioritized_cause(uint32_t cause, uint32_t *type, int16_t *weight)
{
	*type = NSS_INTR_CAUSE_INVALID;
	*weight = 0;

	/*
	 * NOTE: This is a very simple algorithm with fixed weight and strict priority
	 *
	 * TODO: Modify the algorithm later with proper weights and Round Robin
	 */
	if (cause & NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFERS_SOS) {
		*type = NSS_INTR_CAUSE_NON_QUEUE;
		*weight = NSS_EMPTY_BUFFER_SOS_PROCESSING_WEIGHT;
		return NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFERS_SOS;
	}

	if (cause & NSS_REGS_N2H_INTR_STATUS_TX_UNBLOCKED) {
		*type = NSS_INTR_CAUSE_NON_QUEUE;
		*weight = NSS_TX_UNBLOCKED_PROCESSING_WEIGHT;
		return NSS_REGS_N2H_INTR_STATUS_TX_UNBLOCKED;
	}

	if (cause & NSS_REGS_N2H_INTR_STATUS_DATA_COMMAND_QUEUE) {
		*type = NSS_INTR_CAUSE_QUEUE;
		*weight = NSS_DATA_COMMAND_BUFFER_PROCESSING_WEIGHT;
		return NSS_REGS_N2H_INTR_STATUS_DATA_COMMAND_QUEUE;
	}

	if (cause & NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFER_QUEUE) {
		*type = NSS_INTR_CAUSE_QUEUE;
		*weight = NSS_EMPTY_BUFFER_RETURN_PROCESSING_WEIGHT;
		return NSS_REGS_N2H_INTR_STATUS_EMPTY_BUFFER_QUEUE;
	}

	return 0;
}

void nss_core_handle_bh(unsigned long ctx)
{
	uint32_t prio_cause, int_cause;
	int16_t processed, weight;
	uint32_t cause_type;
	struct int_ctx_instance *int_ctx = (struct int_ctx_instance *)ctx;
	struct nss_ctx_instance *nss_ctx = int_ctx->nss_ctx;

	/*
	 * Read cause of interrupt
	 */
	nss_hal_read_interrupt_cause(nss_ctx->nmap, int_ctx->irq, int_ctx->shift_factor, &int_cause);

	do {
		nss_hal_clear_interrupt_cause(nss_ctx->nmap, int_ctx->irq, int_ctx->shift_factor, int_cause);
		while (int_cause) {

			/*
			 * Obtain the cause as per priority. Also obtain the weight
			 *
			 * NOTE: The idea is that all causes are processed as per priority and weight
			 * so that no single cause can overwhelm the system.
			 */
			prio_cause = nss_core_get_prioritized_cause(int_cause, &cause_type, &weight);
			processed = 0;
			switch (cause_type) {
			case NSS_INTR_CAUSE_QUEUE:
				processed = nss_core_handle_cause_queue(nss_ctx, prio_cause, weight);
				break;

			case NSS_INTR_CAUSE_NON_QUEUE:
				processed = nss_core_handle_cause_nonqueue(nss_ctx, prio_cause, weight);
				break;

			default:
				nss_warning("%p: Invalid cause %x received from nss", nss_ctx, int_cause);
				break;
			}

			if (processed <= weight) {
				/*
				 * If we could only manage to process packets lesser
				 * than weight then processing for our queue/cause
				 * is complete and we can clear the cause for this cycle
				 */
				int_cause &= ~prio_cause;
			}
		}

		nss_hal_read_interrupt_cause(nss_ctx->nmap, int_ctx->irq, int_ctx->shift_factor, &int_cause);
	} while (int_cause);

	/*
	 * Re-enable any further interrupt from this IRQ
	 */
	nss_hal_enable_interrupt(nss_ctx->nmap, int_ctx->irq, int_ctx->shift_factor, NSS_HAL_SUPPORTED_INTERRUPTS);

	/*
	 * WARNING: This code should be removed after UBI32 IRQ mask issue is resolved in hardware
	 */
	enable_irq(int_ctx->irq);
}

/*
 * nss_core_send_crypto()
 *	Send crypto buffer to NSS
 */
int32_t nss_core_send_crypto(struct nss_ctx_instance *nss_ctx, void *buf, uint32_t buf_paddr, uint16_t len)
{
	int16_t count, hlos_index, nss_index, size;
	struct h2n_descriptor *desc;
	struct h2n_desc_if_instance *desc_if = &nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].desc_ring;
	struct nss_if_mem_map *if_map = (struct nss_if_mem_map *) nss_ctx->vmap;

	/*
	 * Take a lock for queue
	 */
	spin_lock_bh(&nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].lock);

	/*
	 * We need to work out if there's sufficent space in our transmit descriptor
	 * ring to place the crypto packet.
	 */
	hlos_index = if_map->h2n_hlos_index[NSS_IF_DATA_QUEUE];
	nss_index = if_map->h2n_nss_index[NSS_IF_DATA_QUEUE];

	size = desc_if->size;
	count = ((nss_index - hlos_index - 1) + size) & (size - 1);

	if (unlikely(count < 1)) {
		/* TODO: What is the use case of TX_STOPPED_FLAGS */
		nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].tx_q_full_cnt++;
		nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].flags |= NSS_H2N_DESC_RING_FLAGS_TX_STOPPED;
		spin_unlock_bh(&nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].lock);
		return NSS_CORE_STATUS_FAILURE;
	}

	desc = &(desc_if->desc[hlos_index]);
	desc->opaque = (uint32_t) buf;
	desc->buffer_type = H2N_BUFFER_CRYPTO_REQ;
	desc->buffer = buf_paddr;
	desc->buffer_len = len;
	desc->payload_len = len;
	desc->payload_offs = 0;
	desc->bit_flags = 0;

	/*
	 * Update our host index so the NSS sees we've written a new descriptor.
	 */
	if_map->h2n_hlos_index[NSS_IF_DATA_QUEUE] = (hlos_index + 1) & (size - 1);
	spin_unlock_bh(&nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].lock);

	/*
	 * Memory barrier to ensure all writes have been successful
	 * NOTE: NOCs have internal buffer and hence race condition may occur between NOC
	 *      and register write for interrupt
	 * TODO: Verify and remove if not required
	 */
	wmb();
	return NSS_CORE_STATUS_SUCCESS;
}

/*
 * nss_core_send_buffer()
 *	Send network buffer to NSS
 */
int32_t nss_core_send_buffer(struct nss_ctx_instance *nss_ctx, uint32_t if_num,
					struct sk_buff *nbuf, uint16_t qid,
					uint8_t buffer_type, uint16_t flags)
{
	int16_t count, hlos_index, nss_index, size, mask;
	uint32_t nr_frags;
	struct h2n_desc_if_instance *desc_if = &nss_ctx->h2n_desc_rings[qid].desc_ring;
	struct nss_if_mem_map *if_map = (struct nss_if_mem_map *) nss_ctx->vmap;

	nr_frags = skb_shinfo(nbuf)->nr_frags;
	BUG_ON(nr_frags > MAX_SKB_FRAGS);

	/*
	 * Take a lock for queue
	 */
	spin_lock_bh(&nss_ctx->h2n_desc_rings[qid].lock);

	/*
	 * We need to work out if there's sufficent space in our transmit descriptor
	 * ring to place all of the segments of the nbuf.
	 */
	hlos_index = if_map->h2n_hlos_index[qid];
	nss_index = if_map->h2n_nss_index[qid];

	size = desc_if->size;
	mask = size - 1;
	count = ((nss_index - hlos_index - 1) + size) & (mask);

	if (unlikely(count < (nr_frags + 1))) {
		/*
		 * NOTE: tx_q_full_cnt and TX_STOPPED flags will be used
		 *	when we will add support for DESC Q congestion management
		 *	in future
		 */
		nss_ctx->h2n_desc_rings[qid].tx_q_full_cnt++;
		nss_ctx->h2n_desc_rings[qid].flags |= NSS_H2N_DESC_RING_FLAGS_TX_STOPPED;
		spin_unlock_bh(&nss_ctx->h2n_desc_rings[qid].lock);
		return NSS_CORE_STATUS_FAILURE;
	}

	/*
	 * Is this a conventional unfragmented nbuf?
	 */
	if (likely(nr_frags == 0)) {
		struct h2n_descriptor *desc = &(desc_if->desc[hlos_index]);

		desc->buffer_type = buffer_type;
		desc->bit_flags = flags | H2N_BIT_FLAG_FIRST_SEGMENT | H2N_BIT_FLAG_LAST_SEGMENT;

		if (likely(nbuf->ip_summed == CHECKSUM_PARTIAL)) {
			desc->bit_flags |= H2N_BIT_FLAG_GEN_IP_TRANSPORT_CHECKSUM;
		}

		desc->interface_num = (int8_t)if_num;
		desc->opaque = (uint32_t)nbuf;
		desc->payload_offs = (uint16_t) (nbuf->data - nbuf->head);
		desc->payload_len = nbuf->len;
		desc->buffer_len = (uint16_t)(nbuf->end - nbuf->head);
		desc->buffer = (uint32_t)dma_map_single(NULL, nbuf->head, (nbuf->tail - nbuf->head), DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(NULL, desc->buffer))) {
			spin_unlock_bh(&nss_ctx->h2n_desc_rings[qid].lock);
			return NSS_CORE_STATUS_FAILURE;
		}

	} else {
		/*
		 * TODO: convert to BUGON/ASSERT
		 */
		nss_assert(0);

		/*
		 * TODO: Add support for scatter/gather
		 */
	}

	/*
	 * Update our host index so the NSS sees we've written a new descriptor.
	 */
	if_map->h2n_hlos_index[qid] = (hlos_index + 1) & (mask);
	spin_unlock_bh(&nss_ctx->h2n_desc_rings[qid].lock);

	/*
	 * Memory barrier to ensure all writes have been successful
	 * NOTE: NOCs have internal buffer and hence race condition may occur between NOC
	 *	and register write for interrupt
	 * TODO: Verify and remove if not required
	 */
	wmb();
	return NSS_CORE_STATUS_SUCCESS;
}
