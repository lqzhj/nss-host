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
 * qsdk/qca/src/qca-nss-drv/profiler/profile.c
 *
 *   Implementation for NetAP Profiler
 */

#include <linux/platform_device.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/fs.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/thread_info.h>

#define	NSS_PKT_STATS_ENABLED	0	// nss_core.h has no default DEF for NSS_PKT_STATS_ENABLED
#include "nss_core.h"			// needs only the number of NSS CORES

#include "profilenode.h"
#include "profpkt.h"

/*
 * This is the driver for the NetAP Core profiler.  The system interface to the driver is
 *      profile_register_performance_counter(), defined in <asm/profile.>
 *      a set of proc files (proc/profile/<*>), used by the profiler daemon
 *
 * communication between the profiler components is described in a set of header files.  There are
 * multiple versions of these files that must be kept synchronized:
 *	in nss/source/pkg/profile
 *	in tools/profiler
 *	in qsdk/qca/src/qca-nss-drv/profiler
 *
 * profilesample.h specifies the sample format used by pkg/profile, profile driver, and ip3kprof (two versions)
 * profilenode.h specifies the driver node communication between NetAP and the profile driver. (two versions)
 * profpkt.h specifies the network packet format between the profile driver, profile daemon, and ip3kprof (two versions)
 *
 *
 * NSS profile sampler:
 *	pkg/profile/src/profile.c
 *	pkg/profile/include/profilenode.h
 *	pkg/profile/include/profilesample.h
 *
 * profile driver: this code
 *	qsdk/qca/src/qca-nss-drv/profiler
 *
 * profilerd: the user daemon that sends data to the tool
 *	qsdk/qca/feeds/qca/utils/profilerd
 *
 * ubicom32-prof: the Windows tool
 *	tools/profiler/src/(many files)
 *
 */

#ifndef	PROFILE_DEBUG
#define	profileDebug(fmt, msg...)
#define	profileInfo(fmt, msg...)
#define	profileWarn(fmt, msg...)
#else
#define	profileDebug(fmt, msg...)	printk(KERN_DEBUG fmt, ##msg)
#define	profileInfo(fmt, msg...)	printk(KERN_INFO fmt, ##msg)
#define	profileWarn(fmt, msg...)	printk(KERN_WARNING fmt, ##msg)
#endif

/*
 * LINUX and Ultra counters must all fit in one packet
 */
#define PROFILE_LINUX_MAX_COUNTERS 40
static int profile_num_counters = 0;
static volatile unsigned int *profile_counter[PROFILE_LINUX_MAX_COUNTERS];
static char profile_name[PROFILE_LINUX_MAX_COUNTERS][PROFILE_COUNTER_NAME_LENGTH];

/*
 * internal function to check if @name has been registered before
 * return the found index, or -1 otherwise
 */
static int __profile_find_entry(char *name)
{
	int i;

	for (i = 0; i < profile_num_counters; i++) {
		if (!strncasecmp(name, profile_name[i], PROFILE_COUNTER_NAME_LENGTH)) {
			return i;
		}
	}
	return -1;
}

/*
 * profile_register_performance_counter - register @counter into profile tracking list by key @name
 * @counter: pointer of the counter variable
 * @name: identifier of this counter
 *
 * Returns zero if total entries exceeding PROFILE_LINUX_MAX_COUNTERS
 * non-zero otherwise.
 *
 * Each @name gives unique entry for @counter, by allocating a new array slot or just use existing one.
 * No need of de-registration API, since a loadable module's new insmod, will replace the
 * @counter's * new address at the same profile_counter[] slot.
 */
static int profile_register_performance_counter(volatile unsigned int *counter, char *name)
{
	int i;

	if (profile_num_counters >= PROFILE_LINUX_MAX_COUNTERS) {
		return 0;
	}

	i = __profile_find_entry(name);
	if (i < 0) {
		i = profile_num_counters++;
	}

	profile_counter[i] = counter;
	strncpy(profile_name[i], name, PROFILE_COUNTER_NAME_LENGTH);
	profile_name[i][PROFILE_COUNTER_NAME_LENGTH - 1] = 0;

	return 1;
}

/*
 * make a packet full of sample data
 */
static int profile_make_data_packet(char *buf, int blen, struct profile_io *pn)
{
	int ns;		/* number of samples requested */
	struct profile_header ph;
	struct profile_sample_ctrl_header *psc_hd = &pn->pnc.pn2h->psc_header;

	if (blen < sizeof(ph) + sizeof(struct profile_sample)) {
		return -EINVAL;
	}

	profileDebug("%p stat %x cnt %d %p\n", pn->pnc.pn2h, pn->pnc.pn2h->mh.md_type, psc_hd->count, pn->ccl);

	if (pn->pnc.pn2h->mh.md_type == PINGPONG_EMPTY || psc_hd->count < 1) {
		struct profile_n2h_sample_buf *nsb;
		ns = (pn->ccl_read + 1) & (CCL_SIZE-1);
		nsb = pn->ccl + ns;
		if (ns == pn->ccl_write || nsb->mh.md_type != PINGPONG_FULL) {
			profileInfo("%s: waiting more data %x %p : ns %d rd %d wr %d\n", __func__, nsb->mh.md_type, nsb, ns, pn->ccl_read, pn->ccl_write);
			return -EAGAIN;
		}
		pn->ccl_read = ns;
		profileInfo("sp %p => %p rd %d %p\n", pn->pnc.samples, nsb->samples, ns, nsb);
		psc_hd = &nsb->psc_header;
		pn->pnc.pn2h = nsb;
		pn->pnc.samples = nsb->samples;
		pn->pnc.cur = 0;
	}
	pn->pnc.pn2h->mh.md_type = PINGPONG_INUSE;

	/*
	 * fill in the packet header
	 */
	memset(&ph, 0, sizeof(ph));
	ph.pph.magic = htons(PROF_MAGIC + PROFILE_VERSION);
	ph.pph.header_size = sizeof(ph);
	ph.pph.profile_instructions = 0;
	ph.pph.clock_freq = pn->pnc.un.cpu_freq;
	ph.pph.ddr_freq = pn->pnc.un.ddr_freq;
	ph.pph.cpu_id = pn->pnc.un.cpu_id;
	ph.pph.seq_num = htonl(pn->profile_sequence_num);
	ph.pph.sample_stack_words = htonl(PROFILE_STACK_WORDS);

	ns = (blen - sizeof(ph)) / sizeof(struct profile_sample);
	profileInfo("%X: ns = %d psc_hd count %d phs %d pss %d\n", pn->profile_sequence_num, ns, psc_hd->count, sizeof(ph), sizeof(struct profile_sample));
	if (ns > psc_hd->count)
		ns = psc_hd->count;
	if (ns == 0) {
		printk("NS should not be 0: rlen %d hd cnt %d\n", blen, psc_hd->count);
		return 0;
	}
	ph.pph.sample_count = ns;
	if (copy_to_user(buf, &ph.pph, sizeof(ph.pph)) != 0) {
		return -EFAULT;
	}
	buf += sizeof(ph.pph);

	/*
	 *	ph.exh is unused dummy; and psc_hd->exh is used directly to avoid double mem copy
	 */
	if (copy_to_user(buf, &psc_hd->exh, sizeof(psc_hd->exh)) != 0) {
		return -EFAULT;
	}
	buf += sizeof(psc_hd->exh);

	blen = ns * sizeof(struct profile_sample);
	profileDebug("-profile_make_data_packet %p slen %d cur %d dcped %d + %d\n", pn->pnc.samples, blen, pn->pnc.cur, sizeof(ph.pph), sizeof(psc_hd->exh));
	if (copy_to_user(buf, &pn->pnc.samples[pn->pnc.cur], blen) != 0) {
		return -EFAULT;
	}
	pn->pnc.cur += ns;
	psc_hd->count -= ns;
	if (psc_hd->count < 1)
		pn->pnc.pn2h->mh.md_type = PINGPONG_EMPTY;

	pn->profile_sequence_num++;
	blen += sizeof(ph);
	profileDebug("+profile_make_data_packet %d phd len %d nsp %p rd %d cnt %d\n", blen, sizeof(ph), pn->pnc.pn2h, pn->ccl_read, psc_hd->count);
	return blen;
}

/*
 * This is no longer needed due to NetAP and Linux use different CPUs, and profile is NetAP only.
 * All related code will be removed after corresponging code in visual tool is corrected; otherwise
 * visual tool will mis-behave
 */
struct profile_counter profile_builtin_stats[] =
{
	{
	"Free memory(KB)", 0
	},
	{
	"Max free Block(KB)", 0
	}
};

/*
 * make a packet full of performance counters
 */
static int profile_make_stats_packet(char *buf, int bytes, struct profile_io *pn)
{
	static char prof_pkt[PROFILE_MAX_PACKET_SIZE];

	char *ptr;
	int stat_count;
	int n;
	struct profile_counter counter;
	struct profile_header_counters *hdr = (struct profile_header_counters *)prof_pkt;
	struct profile_sample_ctrl_header *psc_hd = &pn->pnc.pn2h->psc_header;

	if (bytes > PROFILE_MAX_PACKET_SIZE) {
		bytes = PROFILE_MAX_PACKET_SIZE;
	}
	hdr->linux_count = sizeof(profile_builtin_stats) / sizeof(counter);
	stat_count = (bytes - sizeof(hdr)) / sizeof (counter);
	stat_count -= hdr->linux_count;

	if (stat_count <= 0) {
		return 0;
	}

	if (stat_count > pn->pnc.un.num_counters + profile_num_counters) {
		stat_count = pn->pnc.un.num_counters + profile_num_counters;
	}

	hdr->magic = htons(PROF_MAGIC_COUNTERS);
	hdr->ultra_count = htons(stat_count);
	hdr->linux_count = htonl(hdr->linux_count);
	hdr->ultra_sample_time = psc_hd->exh.clocks;
	hdr->linux_sample_time = 0;

	n = stat_count;
	if (n > pn->pnc.un.num_counters)	// copy NSS counters
		n = pn->pnc.un.num_counters;
	n *= sizeof(pn->pnc.un.counters[0]);
	ptr = (char*) (hdr + 1);
	memcpy(ptr, (void *)(pn->pnc.un.counters), n);
	ptr += n;

	for (n = 0; n < profile_num_counters && n + pn->pnc.un.num_counters < stat_count; ++n) {
		counter.value = *(profile_counter[n]);
		strcpy(counter.name, profile_name[n]);
		memcpy(ptr, (void *)(&counter), sizeof(counter));
		ptr += sizeof(counter);
	}

	/*
	 * built in statistics
	profile_get_memory_stats(&total_free, &max_free);
	 */
	profile_builtin_stats[0].value = 0;
	profile_builtin_stats[1].value = 0;
	memcpy(ptr, (void *)profile_builtin_stats, sizeof(profile_builtin_stats));
	ptr += sizeof(profile_builtin_stats);

	n = ptr - prof_pkt;
	if (copy_to_user(buf, prof_pkt, n) != 0) {
		return -EFAULT;
	}
	return n;
}

/*
 * space for all memory blocks so we can hold locks for short time when walking tables
 */
static struct profile_io *node[NSS_MAX_CORES];

static int profile_open(struct inode *inode, struct file *filp)
{
	int	n;
	struct profile_io *pn;

	if (filp->private_data)
		printk(KERN_WARNING "%s: %p\n", filp->f_dentry->d_iname, filp->private_data);

	n = filp->f_dentry->d_iname[strlen(filp->f_dentry->d_iname) - 1] - '0';
	if (n < 0 || n >= NSS_MAX_CORES)
		n = 0;
	pn = node[n];
	if (!pn) {
		return -ENOENT;
	}

	if (!pn->pnc.enabled && nss_get_state(pn->ctx) == NSS_STATE_INITIALIZED) {
		nss_tx_status_t ret;
		pn->pnc.enabled = 1;
		pn->profile_first_packet = 1;
		pn->pnc.un.hd_magic = UBI32_PROFILE_HD_MAGIC | PROFILER_START;
		ret = nss_tx_profiler_if_buf(pn->ctx, (uint8_t *)&pn->pnc.un, sizeof(pn->pnc.un));
		profileInfo("%s: %d -- %p: ccl %p sp %p\n", __func__, ret, pn, pn->ccl, pn->pnc.samples);
		filp->private_data = pn;
		return 0;
	}

	profileWarn("profile ena %d nss stat %x\n", pn->pnc.enabled, nss_get_state(pn->ctx));
	return -EBUSY;
}

/*
 * return a udp packet ready to send to the profiler tool
 * when there are no packets left to make, return 0
 */
static int profile_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
	int result = 0;
	struct profile_io *pn = (struct profile_io *)filp->private_data;
	if (!pn) {
		return -ENOENT;
	}

	if (!pn->pnc.enabled) {
		return -EPERM;
	}
	if (!pn->pnc.samples) {
		return -ENOMEM;
	}

	if (pn->profile_first_packet) {
		result = profile_make_stats_packet(buf, count, pn);
		pn->profile_first_packet = 0;
		profileInfo("%d profile_make_stats_packet %d\n", result, count);
	}

	if (result == 0) {
		result = profile_make_data_packet(buf, count, pn);
		if (result == 0) {
			pn->profile_first_packet = 1;
		}
		profileInfo("%d: profile_make_data_packet %d\n", result, count);
	}

	profileInfo("%d: read %d\n", pn->pnc.enabled, result);
	if (pn->pnc.enabled < 0) {
		nss_tx_status_t ret;
		pn->pnc.enabled = 1;
		pn->pnc.un.hd_magic = UBI32_PROFILE_HD_MAGIC | PROFILER_START;
		ret = nss_tx_profiler_if_buf(pn->ctx, (uint8_t *)&pn->pnc.un, sizeof(pn->pnc.un));
		profileWarn("%s: restart %d -- %p: ccl %p sp %p\n", __func__, ret, pn, pn->ccl, pn->pnc.samples);
	}

	return result;

}

/*
 * the close function paired with profiler_open
 */
static int profile_release(struct inode *inode, struct file *filp)
{
	struct profile_io *pn = (struct profile_io *)filp->private_data;
	if (!pn) {
		return -ENOENT;
	}

	if (pn->pnc.enabled) {
		nss_tx_status_t ret;
		pn->pnc.enabled = 0;
		pn->pnc.un.hd_magic = UBI32_PROFILE_HD_MAGIC | PROFILER_STOP;
		ret = nss_tx_profiler_if_buf(pn->ctx, (uint8_t *)&pn->pnc.un, sizeof(pn->pnc.un));
		profileInfo("%s: %p %d\n", __func__, pn, ret);
		return 0;
	}
	profileWarn("%s: attempt closing non-open dev %p\n", __func__, pn);
	pn->profile_first_packet = 1;
	return -EBADF;
}

#define isspace(c)	(c==' ' || c=='\t')

static int parseDbgData(const char *buf, size_t count, struct debug_box *db)
{
	char *cp;
	int n;

	printk("%p: buf (%s) cnt %d\n", buf, buf, count);
	if (sscanf(buf, "%x", (uint32_t *)&db->base_addr) != 1) {
		printk("%s: cannot get base addr\n", __func__);
		return	-EINVAL;
	}

	cp = strchr(buf, ' ');
	if (!cp) {
noea:		printk("%s: no enough arguments\n", __func__);
		return -EFAULT;
	}

	while (isspace(*cp)) cp++;
	if (!strncmp(cp, "mio", 3) || !strncmp(cp, "moveio", 6)) {
		printk("%p: cp (%s)\n", cp, cp);
		cp = strchr(cp, ' ');
		if (!cp) {
			goto noea;
		}
		db->opts |= DEBUG_OPT_MOVEIO;
	}

	while (isspace(*cp)) cp++;
	printk("base addr %p -- %s\n", db->base_addr, cp);

	if (!strncmp(cp, "read", 4)) {
		cp = strchr(cp, ' ');
		if (cp) {
			while (isspace(*cp)) cp++;
			sscanf(cp, "%x", &db->dlen);
		}
		return 0;
	}

	n = 0;
	do {
		while (isspace(*cp)) cp++;
		if (sscanf(cp, "%x", db->data+n) != 1) {
			printk("n %d : %s\n", n, cp);
			break;
		}
		printk("write %x to off %x\n", db->data[n], n * sizeof(db->data[0]));
		n++;
		cp = strchr(cp, ' ');
	} while (cp && n < MAX_DB_WR);
	return n;
}

/*
 * display memory content read from Phy addr
 */
static void debug_if_show(struct debug_box *db, int buf_len)
{
	int i;

	for (i=0; i < db->dlen; i++) {
		if ((i & 3) == 0)
			printk("\n%p: ", db->base_addr + i);
		printk("%9x", db->data[i]);
	}
	printk("\ndumped %d (extra 1) blen %d\n", db->dlen, buf_len);
}

/*
 * a generic Krait <--> NSS debug interface
 */
static int debug_if(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	int result;
	struct debug_box *db;
	struct profile_io *pio = node[0];

	if (!pio) {
		return -ENOENT;
	}

	if (!pio->pnc.enabled) {
		return -EPERM;
	}

	db = (struct debug_box *) &pio->pnc;
	db->dlen = db->opts = 0;
	result = parseDbgData(buf, count, db);
	if (result < 0) {
		return	result;
	}

	if (!result) {
		db->hd_magic = UBI32_PROFILE_HD_MAGIC | DEBUG_RD_REQ;
	} else {
		db->hd_magic = UBI32_PROFILE_HD_MAGIC | DEBUG_WR_REQ;
		db->dlen = result;
	}
	result = nss_tx_profiler_if_buf(pio->ctx, (uint8_t *)&pio->pnc.un, sizeof(pio->pnc.un));
	printk("dbg res %d dlen = %d opt %x\n", result, db->dlen, db->opts);
	return	count;
}

static const struct file_operations profile_fops = {
	.open		= profile_open,
	.read		= profile_read,
	.release	= profile_release,
	.write		= debug_if,
};

/*
 * showing sample status on Linux console
 */
static int profile_rate_show(struct seq_file *m, void *v)
{
	struct profile_io *pn = node[0];
	if (pn) {
		struct profile_sample_ctrl_header *psc_hd = &pn->pnc.pn2h->psc_header;
		seq_printf(m, "%d samples per second.  %d ultra, %d linux virtual counters.  %d dropped samples.  %d queued of %d max sampels.  %d sent packets.\n",
			pn->pnc.un.rate, pn->pnc.un.num_counters, profile_num_counters, psc_hd->dropped_samples, psc_hd->count, psc_hd->max_samples, pn->profile_sequence_num);
	} else {
		seq_printf(m, "Profiler is not initialized.\n");
	}
	return 0;
}

static int profile_rate_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, profile_rate_show, NULL);
}

static int profile_rate_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	*off = 0;
	return 0;
}

static const struct file_operations profile_rate_fops = {
	.open		= profile_rate_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= profile_rate_write,
};

static void kxdump(void *buf, int len, const char *who)
{
	int *ip = (int*) buf;
	int lns = len >> 5;	// 32-B each line
	if (lns > 4)
		lns = 4;
	printk("%p: kxdump %s: len %d\n", buf, who, len);
	do {
		printk("%x %x %x %x %x %x %x %x\n", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
		ip += 8;
	} while (lns--);
}

static void profile_handle_nss_data(void *arg, uint8_t *buf, uint16_t buf_len)
{
	struct profile_io *pn;
	struct profile_n2h_sample_buf *nsb;
	struct profile_sample_ctrl_header *psc_hd = (struct profile_sample_ctrl_header *)buf;
	int	cmd, wr;
	int	swap = 0;	// only for header and info data, not samples

	if (buf_len < (sizeof(struct profile_session) - sizeof(struct profile_counter) * (PROFILE_MAX_APP_COUNTERS - 1))) {
		printk("profile data packet is too small to be useful %d\n", buf_len);
		return;
	}
	if ((psc_hd->hd_magic & UBI32_PROFILE_HD_MMASK) != UBI32_PROFILE_HD_MAGIC) {
		if ((psc_hd->hd_magic & UBI32_PROFILE_HD_MMASK_REV) != UBI32_PROFILE_HD_MAGIC_REV) {
			kxdump(buf, buf_len, "bad profile packet");
			printk("bad profile packet %x : %d\n", psc_hd->hd_magic, buf_len);
			return;
		}
		profileDebug("Profile data in different Endian type %x\n", psc_hd->hd_magic);
		swap = 1;
		psc_hd->hd_magic = ntohl(psc_hd->hd_magic);
	}
	cmd = psc_hd->hd_magic & ~UBI32_PROFILE_HD_MMASK;

	pn = (struct profile_io *)arg;
	profileInfo("%s: dlen %d swap %d cmd %x - %d\n", __func__, buf_len, swap, cmd, (pn->ccl_read - pn->ccl_write) & (CCL_SIZE-1));
	//kxdump(buf, buf_len, "process profile packet");
	if (cmd == PROFILER_FIXED_INFO) {
		struct profile_session *pTx = (struct profile_session *)buf;
		if (swap) {
			pn->pnc.un.rate = ntohl(pTx->rate);
			pn->pnc.un.cpu_id = ntohl(pTx->cpu_id);
			pn->pnc.un.num_counters = ntohl(pTx->num_counters);
		} else {
			pn->pnc.un = *pTx;
		}
		return;
	}

	if (cmd == DEBUG_REPLY) {
		debug_if_show((struct debug_box*) buf, buf_len);
		return;
	}

	wr = (pn->ccl_write + 1) & (CCL_SIZE-1);
	nsb = pn->ccl + wr;
	swap = (pn->ccl_read - wr) & (CCL_SIZE-1);	// PROFILER_FLOWCTRL
	if (nsb->mh.md_type != PINGPONG_EMPTY || (swap && swap < 5)) {
		if (pn->pnc.enabled > 0) {
			pn->pnc.enabled = -1;
			pn->pnc.un.hd_magic = UBI32_PROFILE_HD_MAGIC | PROFILER_STOP;
			cmd = nss_tx_profiler_if_buf(pn->ctx, (uint8_t *)&pn->pnc.un, sizeof(pn->pnc.un));
			profileWarn("temp stop sampling engine %d\n", cmd);
		}
		if (swap < 3) {
			profileWarn("w%p.%d: %d no room for new profile samples r%p.%d\n", nsb, wr, swap, pn->ccl+pn->ccl_read, pn->ccl_read);
			return;	// -EMSGSIZE
		}
	}
	pn->ccl_write = wr;

	/*
	 * smapling data -- hdr NBO swap is done at NSS side via SWAPB.
	 */
	memcpy(&nsb->psc_header, buf, buf_len); // pn->pnc.pn2h->psc_header = *psc_hd; maybe faster, but take more memory

	nsb->mh.md_type = PINGPONG_FULL;
	//kxdump((void*)(nsb->samples + 23), sizeof(*nsb->samples) << 1, "1st 2 samples");
	profileInfo("filled %p %p wr %d\n", nsb, nsb->samples, pn->ccl_write);
}

/*
 * initialize basic profile data structure
 */
static void profile_init(struct profile_io *node)
{
	int n;

	memset(&node->pnc, 0, sizeof(node->pnc));
	node->ccl_read = 0;
	node->ccl_write = -1;
	node->pnc.pn2h = node->ccl;
	node->pnc.samples = node->ccl->samples;

	for (n=0; n<CCL_SIZE; n++) {
		node->ccl[n].mh.md_type = PINGPONG_EMPTY;
		node->ccl[n].psc_header.count = 0;
	}

	/*
	 * sw_ksp is an array of pointers to struct thread_info, the current task executing for each linux virtual processor
	node->sw_ksp_ptr = sw_ksp;
	 */
	node->task_offset = offsetof(struct thread_info, task);
	node->pid_offset = offsetof(struct task_struct, tgid);
}

static struct proc_dir_entry *pdir;

/*
 * init_module cannot call exit_MODULE, so use this wrapper
 */
void netap_profile_release_resource(void)
{
	if (pdir) {
		remove_proc_entry("rate", pdir);
		remove_proc_entry("data", pdir);
		remove_proc_entry("data1", pdir);
	}
	kfree(node[0]->ccl);
	kfree(node[0]);
	node[0] = NULL;
}

/*
 * kernel module entry
 */
int __init netap_profile_init_module(void)
{
	/*
	 * we need N nodes, not one node + N ctx, for N cores
	 */
	node[0] = kmalloc(sizeof(*node) * NSS_MAX_CORES, GFP_KERNEL);
	if (!node[0]) {
		printk(KERN_INFO "Profiler CTRL kmalloc failed.\n");
		return -ENOMEM;
	}

	node[0]->ccl = kmalloc(sizeof(*node[0]->ccl) * CCL_SIZE * NSS_MAX_CORES, GFP_KERNEL);
	if (!node[0]->ccl) {
		printk(KERN_INFO "Profiler n2h_sample_buf kmalloc failed.\n");
		kfree(node[0]);
		node[0] = NULL;
		return -ENOMEM;
	}

	node[1] = node[0] + 1;
	node[1]->ccl = node[0]->ccl + 1;

	profile_init(node[0]);
	profile_init(node[1]);

	/*
	 * attatch the device callback to N2H channel for CPU 0
	 */
	node[0]->ctx = nss_register_profiler_if(profile_handle_nss_data, NSS_CORE_0, node[0]);
	node[1]->ctx = nss_register_profiler_if(profile_handle_nss_data, NSS_CORE_1, node[1]);


	/*
	 * connect to the file system
	 */
	pdir = proc_mkdir("profile", NULL);
	if (!pdir ||
	    !proc_create("data", 0, pdir, &profile_fops) ||
	    !proc_create("data1", 0, pdir, &profile_fops) ||
	    !proc_create("rate", 0, pdir, &profile_rate_fops)) {
		netap_profile_release_resource();
		return -ENOMEM;
	}

	profile_register_performance_counter(&node[0]->profile_sequence_num, "Profile0 driver data packets");
	profile_register_performance_counter(&node[1]->profile_sequence_num, "Profile1 driver data packets");
	return 0;
}

/*
 * kernel module exit
 */
void __exit netap_profile_exit_module(void)
{
	netap_profile_release_resource();
}

module_init(netap_profile_init_module);
module_exit(netap_profile_exit_module);

MODULE_LICENSE("Dual BSD/GPL");
