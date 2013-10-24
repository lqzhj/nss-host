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
#ifndef __NSS_CRYPTO_CTRL_H
#define __NSS_CRYPTO_CTRL_H

#define NSS_CRYPTO_MAX_IDX	4
#define NSS_CRYPTO_IDX_BITS	~(0x1 << NSS_CRYPTO_MAX_IDX)

/**
 * @brief max key lengths supported for various algorithms
 */
enum nss_crypto_keylen_supp {
	NSS_CRYPTO_KEYLEN_AES128 = 16,		/**< AES-128 bit */
	NSS_CRYPTO_KEYLEN_AES256 = 32,		/**< AES-256 bit */
	NSS_CRYPTO_KEYLEN_SHA1HMAC = 20,	/**< SHA1-HMAC */
};

/**
 * @brief Crypto control specific structure that describes an Engine
 */
struct nss_crypto_ctrl_eng {
	uint32_t cmd_base;	/**< base address for command descriptors (BAM prespective) */
	uint8_t *crypto_base;	/**< base address for crypto register writes */
	uint32_t bam_pbase;	/**< physical base address for BAM register writes */
	uint8_t *bam_base;	/**< base address for BAM regsiter writes */
	uint32_t bam_ee;	/**< BAM execution enivironment for the crypto engine */
	struct device *dev;	/**< HLOS device type for the crypto engine */

	struct nss_crypto_desc *hw_desc[NSS_CRYPTO_BAM_PP]; /**< H/W descriptors BAM rings, command descriptors */
};

/**
 * @brief Main Crypto Control structure, holds information about number of session indexes
 * number of engines etc.,
 *
 * @note currently we support 4 indexes, in future it will allocate more
 */
struct nss_crypto_ctrl {
	uint32_t idx_bitmap;	/**< session allocation bitmap, upto 32 indexes can be used */
	uint32_t num_idxs;	/**< number of allocated indexes */
	uint32_t num_eng;	/**< number of available engines */
	spinlock_t lock;	/**< lock */

	struct nss_crypto_ctrl_eng eng[NSS_CRYPTO_ENGINES];
};

/**
 * @brief Initialize and allocate descriptor memory for a given pipe
 *
 * @param eng[IN] Engine context for control operation
 * @param idx[IN] Pipe pair index number
 * @param desc_paddr[IN] physical address of H/W descriptor
 * @param desc_vaddr[IN] virtual address of H/W descriptor
 *
 */
void nss_crypto_pipe_init(struct nss_crypto_ctrl_eng *eng, uint32_t idx, uint32_t *desc_paddr, struct nss_crypto_desc **desc_vaddr);

/**
 * @brief Initiallize the generic control entities in nss_crypto_ctrl
 */
void nss_crypto_ctrl_init(void);

#endif /* __NSS_CRYPTO_CTRL_H*/
