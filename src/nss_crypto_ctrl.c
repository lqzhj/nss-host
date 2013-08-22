/* Copyright (c) 2013, Qualcomm Atheros Inc.
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
#include <nss_crypto_data.h>

struct nss_crypto_ctrl gbl_crypto_ctrl = {0};

/*
 * Standard initialization vector for SHA-1, source: FIPS 180-2
 */
const uint32_t nss_crypto_fips_sha1_iv[] = {
	0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

/*
 * NULL keys
 */
static const uint8_t null_ckey[NSS_CRYPTO_MAX_KEYLEN_AES];
static const uint8_t null_akey[NSS_CRYPTO_MAX_KEYLEN_SHA1];

#define NSS_CRYPTO_FIPS_SHA1_IV_REGS (sizeof(nss_crypto_fips_sha1_iv)/sizeof(nss_crypto_fips_sha1_iv[0]))

/*
 * nss_crypto_reset_cblk()
 * 	load CMD block with data
 *
 * it will load
 * - crypto register offsets
 * - crypto register values
 */
static inline void nss_crypto_reset_cblk(struct nss_crypto_bam_cmd *cmd, uint32_t addr, uint32_t value)
{
	cmd->addr = CRYPTO_CMD_ADDR(addr);
	cmd->value = value;
	cmd->mask = CRYPTO_MASK_ALL;
}
/*
 * nss_crypto_setup_cmn_cblk()
 * 	this setups the common parts of command block
 *
 * The command block constitutes of common portion applicable for encryption & authentication.
 * This routine setups the common portion like configs, go_proc etc.
 */
static void nss_crypto_setup_cmn_cblk(uint32_t base_addr, struct nss_crypto_cache_cmdblk *cmd, uint32_t idx)
{
	uint32_t cfg_value = 0;
	uint32_t beat;

	/*
	 * setup pipe unlock descriptor
	 */
	nss_crypto_reset_cblk(&cmd->unlock, CRYPTO_DEBUG_ENABLE + base_addr, 0x1);

	/*
	 * Configuration programming
	 * - beats
	 * - interrupts
	 * - pipe number for the crypto transaction
	 */
	beat = CRYPTO_BURST2BEATS(CRYPTO_MAX_BURST);
	cfg_value = (CRYPTO_CONFIG_DOP_INTR | CRYPTO_CONFIG_DIN_INTR |
			CRYPTO_CONFIG_DOUT_INTR | CRYPTO_CONFIG_PIPE_SEL(idx) |
			CRYPTO_CONFIG_REQ_SIZE(beat));

	/*
	 * The below programming pre-fills the crypto register offset
	 * addresses and the bitmask for the value to be pushed through
	 * the command block. The bitmask is used by the BAM to identify
	 * how many bits are valid in the 'value' of the command block,
	 * it uses that mask to only program the bits that are valid.
	 */
	nss_crypto_reset_cblk(&cmd->config_0, CRYPTO_CONFIG + base_addr, cfg_value);
	nss_crypto_reset_cblk(&cmd->seg_size, CRYPTO_SEG_SIZE + base_addr, 0);
	nss_crypto_reset_cblk(&cmd->config_1, CRYPTO_CONFIG + base_addr, (cfg_value | CRYPTO_CONFIG_LITTLE_ENDIAN));
	nss_crypto_reset_cblk(&cmd->go_proc, CRYPTO_GO_PROC + base_addr, (CRYPTO_GOPROC_SET | CRYPTO_GOPROC_RESULTS_DUMP));
}

/*
 * nss_crypto_setup_cipher_cblk()
 * 	this routine setups the cipher specific command block
 *
 * this routine will do the following
 * - cipher segment configuration
 * - cipher segment size
 * - cipher segment address
 * - cipher iv
 * - cipher counter mask
 */
static void nss_crypto_setup_cipher_cblk(uint32_t base_addr, struct nss_crypto_cache_cmdblk *cmd, uint32_t val)
{
	int i;

	nss_crypto_reset_cblk(&cmd->encr_seg_cfg, CRYPTO_ENCR_SEG_CFG + base_addr, val);
	nss_crypto_reset_cblk(&cmd->encr_seg_size, CRYPTO_ENCR_SEG_SIZE + base_addr, 0);
	nss_crypto_reset_cblk(&cmd->encr_seg_start, CRYPTO_ENCR_SEG_START + base_addr, 0);
	nss_crypto_reset_cblk(&cmd->encr_ctr_msk, CRYPTO_ENCR_CNTR_MASK + base_addr, 0xffffffff);

	for (i = 0; i < NSS_CRYPTO_CIV_REGS; i++) {
		nss_crypto_reset_cblk(&cmd->encr_iv[i], CRYPTO_ENCR_IVn(i) + base_addr, 0);
	}
}

/*
 * nss_crypto_setup_auth_cblk()
 * 	this will program the authentication specific command block portions
 *
 * this routine will do the following
 * - auth segment configuration
 * - auth segment size
 * - auth iv
 */
static inline void nss_crypto_setup_auth_cblk(uint32_t base_addr, struct nss_crypto_cache_cmdblk *cmd, uint32_t val, uint32_t *iv, uint32_t iv_regs)
{
	uint32_t iv_val;
	int i;

	nss_crypto_reset_cblk(&cmd->auth_seg_cfg, CRYPTO_AUTH_SEG_CFG + base_addr, val);
	nss_crypto_reset_cblk(&cmd->auth_seg_size, CRYPTO_AUTH_SEG_SIZE + base_addr, 0);
	nss_crypto_reset_cblk(&cmd->auth_seg_start, CRYPTO_AUTH_SEG_START + base_addr, 0);

	nss_crypto_assert(iv_regs <= NSS_CRYPTO_AIV_REGS);

	for (i = 0; i < NSS_CRYPTO_AIV_REGS; i++) {
		iv_val = (i < iv_regs) ? iv[i] : 0;
		nss_crypto_reset_cblk(&cmd->auth_iv[i], CRYPTO_AUTH_IVn(i) + base_addr, iv_val);
	}
}

/*
 * nss_crypto_bam_init()
 * 	initialize  the BAM pipe; pull it out reset and load its configuration
 */
int nss_crypto_bam_pipe_init(struct nss_crypto_ctrl_eng *ctrl, uint32_t pipe)
{
	uint32_t cfg;

	cfg = (CRYPTO_BAM_P_CTRL_DIRECTION(pipe) | CRYPTO_BAM_P_CTRL_SYS_MODE |
		CRYPTO_BAM_P_CTRL_LOCK_GROUP(NSS_CRYPTO_INPIPE(pipe)));

	/*
	 * Put and Pull BAM pipe from reset
	 */
	iowrite32(0x1, ctrl->bam_base + CRYPTO_BAM_P_RST(pipe));
	iowrite32(0x0, ctrl->bam_base + CRYPTO_BAM_P_RST(pipe));

	iowrite32(cfg, ctrl->bam_base + CRYPTO_BAM_P_CTRL(pipe));

	nss_crypto_dbg("BAM_CTRL = 0x%x, pipe = %d\n", ioread32(ctrl->bam_base + CRYPTO_BAM_P_CTRL(pipe)), pipe);

	return 0;
}

/*
 * nss_crypto_desc_alloc()
 * 	allocate crypto descriptor memory from DDR
 *
 * this allocates coherent memory for crypto descriptors, the pipe initialization should
 * tell the size
 */
void *nss_crypto_desc_alloc(uint32_t *paddr, uint32_t size)
{
	uint32_t new_size;
	void *ret_addr;

	new_size = size + NSS_CRYPTO_DESC_ALIGN;

	ret_addr = dma_alloc_coherent(NULL, new_size, paddr, GFP_DMA);
	if (!ret_addr) {
		nss_crypto_err("OOM: unable to allocate coherent memory of size(%dKB)\n", (new_size/1000));
		return NULL;
	}

	memset(ret_addr, 0x0, new_size);

	ret_addr = (void *)ALIGN((uint32_t)ret_addr, NSS_CRYPTO_DESC_ALIGN);

	return ret_addr;
}

/*
 * nss_crypto_pipe_init()
 * 	initialize the crypto pipe
 *
 * this will
 * - configure the BAM pipes
 * - allocate the descriptors
 * - program the BAM descriptors with the command blocks (lock/unlock)
 * - update the BAM registers for the ring locations
 */
void
nss_crypto_pipe_init(struct nss_crypto_ctrl_eng *eng, uint32_t idx, uint32_t *desc_paddr, struct nss_crypto_desc **desc_vaddr)
{
	struct nss_crypto_desc *desc;
	uint32_t in_pipe, out_pipe;
	uint32_t in_pipe_sz, out_pipe_sz;
	uint32_t unlock_sz, cmd0_sz, cmd1_sz;
	uint32_t paddr;
	uint32_t cblk_start;
	int i;

	/*
	 * Init the Crypto Core
	 */
	in_pipe = nss_crypto_idx_to_inpipe(idx);
	out_pipe = nss_crypto_idx_to_outpipe(idx);

	in_pipe_sz = sizeof(struct nss_crypto_in_trans) * NSS_CRYPTO_MAX_QDEPTH;
	out_pipe_sz = sizeof(struct nss_crypto_out_trans) * NSS_CRYPTO_MAX_QDEPTH;

	nss_crypto_bam_pipe_init(eng, in_pipe);
	nss_crypto_bam_pipe_init(eng, out_pipe);

	/*
	 * Allocate descriptors
	 */
	desc = nss_crypto_desc_alloc(&paddr, NSS_CRYPTO_DESC_SZ);

	*desc_paddr = paddr;
	*desc_vaddr = desc;

	/*
	 * write input BAM ring
	 */
	iowrite32(paddr, eng->bam_base + CRYPTO_BAM_P_DESC_FIFO_ADDR(in_pipe));
	iowrite32(in_pipe_sz, eng->bam_base + CRYPTO_BAM_P_FIFO_SIZES(in_pipe));

	/*
	 * write output BAM ring
	 */
	iowrite32(paddr + in_pipe_sz, eng->bam_base + CRYPTO_BAM_P_DESC_FIFO_ADDR(out_pipe));
	iowrite32(out_pipe_sz, eng->bam_base + CRYPTO_BAM_P_FIFO_SIZES(out_pipe));

	/*
	 * we are done with input and output rings, move the cursor to the command block
	 */
	paddr = paddr + in_pipe_sz + out_pipe_sz;

	/*
	 * this loop pre-fills the pipe rings with the command blocks, the data path will
	 * no longer need to write the command block locations when sending the packets for
	 * encryption/decryption. The idea header is to avoid as much as possible the writes
	 * to the uncached locations.
	 */
	unlock_sz = NSS_CRYPTO_BAM_CMD_SZ;
	cmd0_sz = offsetof(struct nss_crypto_cache_cmdblk, config_1);
	cmd1_sz = NSS_CRYPTO_CACHE_CBLK_SZ - cmd0_sz - unlock_sz;

	for (i = 0; i < NSS_CRYPTO_MAX_QDEPTH; i++) {
		cblk_start = paddr + (NSS_CRYPTO_CACHE_CBLK_SZ * i);

		/*
		 * program CMD0 (encr configs & auth configs)
		 */
		desc->in[i].cmd0_lock.data_len = cmd0_sz;
		desc->in[i].cmd0_lock.data_start = cblk_start;
		desc->in[i].cmd0_lock.flags = (CRYPTO_BAM_DESC_CMD | CRYPTO_BAM_DESC_LOCK);

		/*
		 * program CMD1 (config & go_proc)
		 */
		desc->in[i].cmd1.data_len = cmd1_sz;
		desc->in[i].cmd1.data_start = cblk_start + cmd0_sz;
		desc->in[i].cmd1.flags = CRYPTO_BAM_DESC_CMD;

		desc->in[i].data.flags = (CRYPTO_BAM_DESC_EOT|CRYPTO_BAM_DESC_NWD);

		/*
		 * program CM3 (unlock)
		 */
		desc->in[i].cmd3_unlock.data_len = unlock_sz;
		desc->in[i].cmd3_unlock.data_start = cblk_start + cmd0_sz + cmd1_sz;
		desc->in[i].cmd3_unlock.flags = (CRYPTO_BAM_DESC_CMD | CRYPTO_BAM_DESC_UNLOCK);

		desc->out[i].data.flags = 0;

		/*
		 * program results dump
		 */
		desc->out[i].results.data_len = NSS_CRYPTO_RESULTS_SZ;
	}

	nss_crypto_info("init completed for Pipe Pair[%d]\n", idx);
	nss_crypto_dbg("total size - %d, qdepth - %d, in_sz - %d, out_sz - %d, cmd_sz - %d\n", NSS_CRYPTO_DESC_SZ, NSS_CRYPTO_MAX_QDEPTH,
			in_pipe_sz, out_pipe_sz, (cmd0_sz + cmd1_sz + unlock_sz));

}

/*
 * nss_crypto_program_ckeys()
 * 	this will program cipher key registers with new keys
 */
void nss_crypto_program_ckeys(uint8_t *base, uint32_t idx, uint8_t *key, uint32_t key_sz)
{
	uint32_t key_val, *key_ptr;
	int i;

	for (i = 0; i < (key_sz / sizeof(uint32_t)) ; i++) {
		key_ptr = (uint32_t *)&key[i * 4];
		key_val = cpu_to_be32(*key_ptr);

		iowrite32(key_val, base + CRYPTO_ENCR_PIPEm_KEYn(idx, i));

		nss_crypto_dbg("creg[%d] = 0x%02x ", i, key_val);
	}

}

/*
 * nss_crypto_program_akeys()
 * 	this will program authentication key registers with new keys
 */
void nss_crypto_program_akeys(uint8_t *base, uint32_t idx, uint8_t *key, uint32_t key_sz)
{
	uint32_t key_val, *key_ptr;
	int i;

	for (i = 0; i < (key_sz / sizeof(uint32_t)); i++) {
		key_ptr = (uint32_t *)&key[i * 4];
		key_val = cpu_to_be32(*key_ptr);

		iowrite32(key_val, base + CRYPTO_AUTH_PIPEm_KEYn(idx, i));

		nss_crypto_dbg("areg[%d] = 0x%02x ", i, key_val);
	}
}

/*
 * nss_crypto_validate_cipher()
 * 	for a given cipher check whether the programming done by CFI is valid
 *
 * this is supposed to verify the
 * - that the algorithm is supported
 * - that key size is supported
 */
nss_crypto_status_t nss_crypto_validate_cipher(struct nss_crypto_key *cipher, uint32_t *mask, uint32_t *key_sz)
{
	switch (cipher->algo) {
	case NSS_CRYPTO_CIPHER_AES:
		nss_crypto_assert(cipher->key_len <= NSS_CRYPTO_MAX_KEYLEN_AES);

		switch (cipher->key_len) {
		case NSS_CRYPTO_KEYLEN_AES128:
			*mask = (CRYPTO_ENCR_SEG_CFG_ALG_AES | CRYPTO_ENCR_SEG_CFG_MODE_CBC);
			*mask |= CRYPTO_ENCR_SEG_CFG_KEY_AES128;
			/*
			 * XXX: this needs to be flexible such that uncached keys can also
			 * be sent on the same pipe
			 */
			*mask |= CRYPTO_ENCR_SEG_CFG_PIPE_KEYS;
			*key_sz = NSS_CRYPTO_KEYLEN_AES128;

			break;

		case NSS_CRYPTO_KEYLEN_AES256:
			*mask = (CRYPTO_ENCR_SEG_CFG_ALG_AES | CRYPTO_ENCR_SEG_CFG_MODE_CBC);
			*mask |= CRYPTO_ENCR_SEG_CFG_KEY_AES256;
			*mask |= CRYPTO_ENCR_SEG_CFG_PIPE_KEYS;
			*key_sz = NSS_CRYPTO_KEYLEN_AES256;
			break;

		default:
			/*
			 * we don't support zero key length programming
			 */
			*mask = 0;
			*key_sz = 0;

			nss_crypto_err("invalid AES key length (%d)\n", cipher->key_len);
			return NSS_CRYPTO_STATUS_EINVAL;
		}

		break;

	case NSS_CRYPTO_CIPHER_NONE:
		/*
		 * no cipher will be used for flushing out older key entries
		 */
		*mask = 0;
		*key_sz = NSS_CRYPTO_MAX_KEYLEN_AES;

		break;

	default:
		*mask = 0;
		*key_sz = 0;

		nss_crypto_err("unsupported cipher algorithm = %d\n", cipher->algo);
		return NSS_CRYPTO_STATUS_EINVAL;
	}

	return NSS_CRYPTO_STATUS_OK;
}

/*
 * nss_crypto_validate_auth()
 * 	for a given auth validate the programming done by CFI
 *
 * this is supposed to verify the
 * - that the algorithm is supported
 * - that key size is supported
 */
nss_crypto_status_t nss_crypto_validate_auth(struct nss_crypto_key *auth, uint32_t *mask, uint32_t *key_sz, uint32_t **iv, uint32_t *iv_regs)
{
	switch (auth->algo) {
	case NSS_CRYPTO_AUTH_SHA1_HMAC:

		if (auth->key_len != NSS_CRYPTO_KEYLEN_SHA1HMAC) {
			return NSS_CRYPTO_STATUS_EINVAL;
		}

		*iv = (uint32_t *)&nss_crypto_fips_sha1_iv[0];
		*iv_regs = NSS_CRYPTO_FIPS_SHA1_IV_REGS;

		*mask = CRYPTO_AUTH_SEG_CFG_MODE_HMAC;
		*mask |= (CRYPTO_AUTH_SEG_CFG_ALG_SHA | CRYPTO_AUTH_SEG_CFG_SIZE_SHA1);
		*mask |= (CRYPTO_AUTH_SEG_CFG_FIRST | CRYPTO_AUTH_SEG_CFG_LAST);
		/*
		 * XXX: this needs to be flexible such that uncached keys can also
		 * be sent on the same pipe
		 */
		*mask |= CRYPTO_AUTH_SEG_CFG_PIPE_KEYS;

		*key_sz = NSS_CRYPTO_KEYLEN_SHA1HMAC;

		break;

	case NSS_CRYPTO_AUTH_NONE:
		/*
		 * no auth will be used for flushing out older key entries
		 */
		*iv = NULL;
		*iv_regs = 0;
		*mask = 0;
		*key_sz = NSS_CRYPTO_MAX_KEYLEN_SHA1;

		break;

	default:
		*iv = NULL;
		*iv_regs = 0;
		*mask = 0;
		*key_sz = 0;

		nss_crypto_err("unsupported auth algorithm = %d\n", auth->algo);

		return NSS_CRYPTO_STATUS_EINVAL;
	}

	return NSS_CRYPTO_STATUS_OK;
}

/*
 * nss_crypto_key_update()
 * 	update the newly arrived keys/algorithm from session alloc
 *
 * this will do the following
 * - pre-fill the command blocks with cipher/auth specific data
 * - write new keys to the cipher/auth registers
 *
 */
nss_crypto_status_t nss_crypto_key_update(struct nss_crypto_ctrl_eng *eng, uint32_t idx, struct nss_crypto_key *cipher, struct nss_crypto_key *auth)
{
	struct nss_crypto_desc *desc;
	uint32_t key_sz;
	uint32_t mask;
	nss_crypto_status_t status;
	uint32_t *iv, iv_regs;
	int i = 0;

	desc = eng->hw_desc[idx];

	/*
	 * common setup
	 */
	nss_crypto_info("key update for cipher_algo = %d, auth_algo = %d \n", cipher->algo, auth->algo);

	for (i = 0; i < NSS_CRYPTO_MAX_QDEPTH; i++) {
		nss_crypto_setup_cmn_cblk(eng->cmd_base, &desc->cblk[i], idx);

	}

	/*
	 * cipher setup
	 */
	status = nss_crypto_validate_cipher(cipher, &mask, &key_sz);
	if (status != NSS_CRYPTO_STATUS_OK) {
		return status;
	}

	nss_crypto_dbg("cipher key\n");

	nss_crypto_program_ckeys(eng->crypto_base, idx, cipher->key, key_sz);

	nss_crypto_dbg("\n");

	/*
	 * initialize the command blocks with new cipher data
	 */
	for (i = 0; i < NSS_CRYPTO_MAX_QDEPTH; i++) {
		nss_crypto_setup_cipher_cblk(eng->cmd_base, &desc->cblk[i], mask);

	}

	/**
	 * Authentication setup
	 */
	status = nss_crypto_validate_auth(auth, &mask, &key_sz, &iv, &iv_regs);
	if (status != NSS_CRYPTO_STATUS_OK) {
		return status;
	}

	nss_crypto_program_akeys(eng->crypto_base, idx, auth->key, key_sz);

	for (i = 0; i < NSS_CRYPTO_MAX_QDEPTH; i++) {
		nss_crypto_setup_auth_cblk(eng->cmd_base, &desc->cblk[i], mask, iv, iv_regs);
	}

	return status;
}

/*
 * nss_crypto_bam_pipe_enable()
 * 	enable the crypto BAM pipe for crypto operations
 *
 * Usually required to turn on the pipes which will be used
 */
static void nss_crypto_bam_pipe_enable(struct nss_crypto_ctrl_eng *ctrl, uint32_t pipe)
{
	uint32_t ctrl_reg;

	ctrl_reg = ioread32(ctrl->bam_base + CRYPTO_BAM_P_CTRL(pipe));
	ctrl_reg |= CRYPTO_BAM_P_CTRL_EN;
	iowrite32(ctrl_reg, ctrl->bam_base + CRYPTO_BAM_P_CTRL(pipe));
}

/*
 * nss_crypto_bam_pipe_disable()
 * 	disable the crypto BAM pipe for crypto operations
 *
 * Usually required to turn off the pipes which will not be used
 */
static void nss_crypto_bam_pipe_disable(struct nss_crypto_ctrl_eng *ctrl, uint32_t pipe)
{
	uint32_t ctrl_reg;

	ctrl_reg = ioread32(ctrl->bam_base + CRYPTO_BAM_P_CTRL(pipe));
	ctrl_reg &= ~CRYPTO_BAM_P_CTRL_EN;
	iowrite32(ctrl_reg, ctrl->bam_base + CRYPTO_BAM_P_CTRL(pipe));
}

/*
 * nss_crypto_session_alloc()
 * 	allocate a new crypto session for operation
 */
int32_t nss_crypto_session_alloc(nss_crypto_handle_t crypto, struct nss_crypto_key *cipher, struct nss_crypto_key *auth)
{
	struct nss_crypto_ctrl *ctrl = &gbl_crypto_ctrl;
	struct nss_crypto_key null_cipher = {0}, null_auth = {0};
	int32_t idx;
	int i;



	spin_lock_bh(&ctrl->lock); /* index lock*/

	if (ctrl->num_idxs >= NSS_CRYPTO_MAX_IDX) {
		spin_unlock_bh(&ctrl->lock); /* index unlock*/
		nss_crypto_err("crypto index table full\n");
		return -1;
	}

	idx = ffz(ctrl->idx_bitmap);
	ctrl->num_idxs++;
	ctrl->idx_bitmap |= (0x1 << idx);

	/*
	 * We need to handle cases when pure cipher or pure auth is programmed
	 * in any of these cases the other one will need to have zero keys
	 */
	if (!cipher) {
		null_cipher.algo = NSS_CRYPTO_CIPHER_NONE;
		null_cipher.key  = (uint8_t *)&null_ckey[0];
		cipher = &null_cipher;
	}

	if (!auth) {
		null_auth.algo = NSS_CRYPTO_AUTH_NONE;
		null_auth.key  = (uint8_t *)&null_akey[0];
		auth = &null_auth;
	}

	/*
	 * program keys for all the engines for the given pipe pair (index)
	 */
	for (i = 0; i < ctrl->num_eng; i++) {
		nss_crypto_key_update(&ctrl->eng[i], idx, cipher, auth);
		nss_crypto_bam_pipe_enable(&ctrl->eng[i], nss_crypto_idx_to_inpipe(idx));
		nss_crypto_bam_pipe_enable(&ctrl->eng[i], nss_crypto_idx_to_outpipe(idx));
	}

	spin_unlock_bh(&ctrl->lock); /* index unlock*/

	nss_crypto_info("allocated new index (used - %d, max - %d)\n", ctrl->num_idxs, NSS_CRYPTO_MAX_IDX);
	nss_crypto_dbg("index bitmap = 0x%x, index assigned = %d\n", ctrl->idx_bitmap, idx);

	return idx;
}
EXPORT_SYMBOL(nss_crypto_session_alloc);

/*
 * nss_crypto_session_free()
 * 	free the crypto session, that was previously allocated
 */
void nss_crypto_session_free(nss_crypto_handle_t crypto, uint32_t idx)
{
	struct nss_crypto_ctrl *ctrl = &gbl_crypto_ctrl;
	struct nss_crypto_key null_cipher = {0}, null_auth = {0};
	uint32_t idx_map;
	int i;

	idx_map = (0x1 << idx);

	/*
	 * the only way to flush the keys from H/W is to load it
	 * with zeros
	 */
	null_cipher.algo = NSS_CRYPTO_CIPHER_NONE;
	null_cipher.key  = (uint8_t *)&null_ckey[0];

	null_auth.algo = NSS_CRYPTO_AUTH_NONE;
	null_auth.key  = (uint8_t *)&null_akey[0];

	spin_lock_bh(&ctrl->lock); /* index lock*/

	if (!ctrl->num_idxs || ((ctrl->idx_bitmap & idx_map) != idx_map)) {
		spin_unlock_bh(&ctrl->lock);
		nss_crypto_err("crypto index(%d) is invalid\n", idx);
		return;
	}
	/*
	 * program keys for all the engines for the given pipe pair (index)
	 */
	for (i = 0; i < ctrl->num_eng; i++) {
		nss_crypto_key_update(&ctrl->eng[i], idx, &null_cipher, &null_auth);
		nss_crypto_bam_pipe_disable(&ctrl->eng[i], idx * 2);
		nss_crypto_bam_pipe_disable(&ctrl->eng[i], (idx * 2) + 1);
	}

	ctrl->idx_bitmap &= ~(0x1 << idx);
	ctrl->num_idxs--;

	spin_unlock_bh(&ctrl->lock); /* index unlock*/

	nss_crypto_info("deallocated index (used - %d, max - %d)\n", ctrl->num_idxs, NSS_CRYPTO_MAX_IDX);
	nss_crypto_info("index freed  = 0x%x, index = %d\n", ctrl->idx_bitmap, idx);
}
EXPORT_SYMBOL(nss_crypto_session_free);

/*
 * nss_crypto_ctrl_init()
 * 	initialize the crypto control
 */
void nss_crypto_ctrl_init(void)
{
	spin_lock_init(&gbl_crypto_ctrl.lock);

	gbl_crypto_ctrl.idx_bitmap = 0;
	gbl_crypto_ctrl.num_eng = 0;
	gbl_crypto_ctrl.num_idxs = 0;
}
