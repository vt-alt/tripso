/*
 * Netfilter module to translate between CIPSO and RFC 1108 (Astra)
 * security labels.
 *
 * Copyright (C) 2018 vt@altlinux.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <asm/unaligned.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/bitrev.h>
#include <linux/netfilter/x_tables.h>
#include <net/cipso_ipv4.h>
#include "xt_TRIPSO.h"

#define XT_TRIPSO_VERSION VERSION
MODULE_AUTHOR("<vt@altlinux.org>");
MODULE_DESCRIPTION("iptables target for security label translation");
MODULE_LICENSE("GPL");
MODULE_VERSION(XT_TRIPSO_VERSION);
MODULE_ALIAS("ipt_TRIPSO");

static unsigned int doi __read_mostly = 1;
module_param(doi, uint, 0664);
MODULE_PARM_DESC(doi, "domain of interpretation (default=1)");
static unsigned int debug __read_mostly = 0;
module_param(debug, uint, 0664);
MODULE_PARM_DESC(debug, "debug level");
static unsigned int icmp __read_mostly = 1;
module_param(icmp, uint, 0664);
MODULE_PARM_DESC(icmp, "send ICMP on errors (default=1)");

/* Extract rfc1108 packed flags into array. */
static int unpack_rfc1108_bits(const uint8_t *data, size_t len, uint8_t *out, size_t size)
{
	unsigned int i;
	unsigned int acc = 0;
	unsigned int bits = 0;

	for (i = 0; i < len; i++) {
		const uint8_t b = data[i];

		if ((b >> 1) && !size) {
			/* `acc` could accumulate big amount of zero bits that
			 * could exceed its size if turned to significant bits,
			 * instaerror if significant bits are incoming and
			 * output buffer is already chocked */
			return -1;
		}
		acc |= (b >> 1) << bits;
		bits += 7;
		while (bits >= 8) {
			/* any significant bits exceeding output buffer will
			 * trigger a error */
			if (size) {
				*out++ = acc & 0xff;
				size--;
				acc >>= 8;
				bits -= 8;
			} else if (acc) {
				/* not triggering error on zero `acc` will allow
				 * to accumulate insignificant zero bits */
				return -1;
			}
		}
		if (!(b & 1))
			break;
	}
	/* garbage behind uncontinued byte until option end is silently
	 * discarded */
	while (acc) {
		if (size) {
			*out++ = acc & 0xff;
			size--;
			acc >>= 8;
			bits -= 8;
		} else
			return -1;
	}
	/* higher bits that is not presented in the input assumed to be zeros */
	while (size) {
		*out++ = 0;
		size--;
	}

	return 0;
}

/* Copy variable len (bit-)array filling another with sanity checks
 * and stripping insignificant bits if need. */
static int copy_msb0_bits(const uint8_t *data, size_t len, uint8_t *out, size_t size)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		const uint8_t b = data[i];

		if (size) {
			*out++ = b;
			size--;
		} else if (b)
			return 1;
	}
	while (size) {
		*out++ = 0;
		size--;
	}
	return 0;
}

static uint64_t bitrev64(uint64_t x)
{
	return ((uint64_t)bitrev32(x) << 32) |
		(uint64_t)bitrev32(x >> 32);
}

/* Extract level and categories from RFC 1108 Basic Security label */
/* Label in RFC 1108 is originally encoded as:
 * [0]   130 = IPOPT_SEC
 * [1]   length >= 3
 * [2]   classification level (lower value is higher secrecy) [4 levels]
 * [3].. protection authority flags (msb0)
 *       * lsb of each byte since [3] is flag of presence of next byte
 *
 * Astra mod:
 * [0]   130 = IPOPT_SEC
 * [1]   length >= 4
 * [2]   classification level is Unclassified (0b10101011)
 * [3]   level (higher value higher secrecy) [256 levels]
 * [4].. categories (lsb0)
 *       * lsb of each byte since [3] is flag of presence of next byte
 *
 */
static int parse_rfc1108_astra(const uint8_t *data, uint16_t len, uint8_t *level, uint64_t *categories)
{
	uint8_t parsec[9];

	if (data[1] < 3)
		return 0;
	if (data[2] != 0b10101011) /* Unclassified */
		return 0;
	/* Astra allows 64-bit of category flags */
	if (data[1] < 4)
		return 0;

	if (unpack_rfc1108_bits(&data[3], len - 3, parsec, sizeof(parsec)))
		return 0;

	*level = parsec[0];
	*categories = get_unaligned_le64(&parsec[1]);
	if (debug > 1)
		pr_devel(": astra level=%u categories=%llx\n", *level, *categories);

	return 1;
}

#define CIPSO_V4_OPT_LEN_MAX          40
#define CIPSO_V4_HDR_LEN              6
#define CIPSO_V4_TAG_RBM_BLEN         4
#define CIPSO_V4_OPT_LEN (CIPSO_V4_HDR_LEN + CIPSO_V4_TAG_RBM_BLEN)

/* Extract level and categories from cipso option. */
/* CIPSO option is encoded like this:
 * [0]     134 = IPOPT_CIPSO
 * [1]     length <= 40
 * [2..5]  DOI >= 1
 * tags:
 *  [6]    tag type (1 for bitmap)
 *  [7]    length of tag (4..34)
 *  [8]    empty alignment byte
 *  [9]    sensitivity level
 *  [10..] categories bitmap (msb0-be) (0..30 octets)
 * [another tag...]
 */
static int parse_cipso(const uint8_t *data, uint16_t len, uint8_t *level, uint64_t *categories)
{
	if (data[1] <= CIPSO_V4_HDR_LEN || data[1] > CIPSO_V4_OPT_LEN_MAX)
		return 0;
	if (doi != get_unaligned_be32(&data[2]))
		return 0;
	data += CIPSO_V4_HDR_LEN;
	len  -= CIPSO_V4_HDR_LEN;
	/* parse tags */
	while (len > 0) {
		if (len < CIPSO_V4_TAG_RBM_BLEN
		    || data[1] < CIPSO_V4_TAG_RBM_BLEN
		    || data[1] > len)
			return 0;
		*level = data[3];

		if (data[0] == CIPSO_V4_TAG_RBITMAP) {
			if (copy_msb0_bits(&data[4], data[1] - 3,
				    (uint8_t *)categories, sizeof(*categories)))
				return 0;
			*categories = bitrev64(be64_to_cpu(*categories));
			break;
		} else {
			/* two other tag types */
			return 0;
		}
	}
	if (debug > 1)
		pr_devel(": cipso level=%u categories=%llx\n", *level, *categories);
	return 1;
}

/* Store CIPSO option in a buffer.
 * return number of stored bytes or negative on error */
static int write_cipso(uint8_t *data, uint16_t len, uint8_t level, uint64_t categories)
{
	uint8_t cat[8];
	int i, catlen = -1;

	categories = cpu_to_le64(categories);
	for (i = 0; i < sizeof(cat); i++) {
		if ((cat[i] = bitrev8(((uint8_t *)(&categories))[i])))
			catlen = i;
	}
	catlen++;

	if (CIPSO_V4_OPT_LEN + catlen > len)
		return -ENOMEM;
	data[0] = IPOPT_CIPSO;
	data[1] = CIPSO_V4_OPT_LEN + catlen;
	put_unaligned_be32(doi, &data[2]);
	data[6] = CIPSO_V4_TAG_RBITMAP;
	data[7] = CIPSO_V4_TAG_RBM_BLEN + catlen;
	data[8] = 0; /* alignment byte */
	data[9] = level;
	memcpy(&data[10], &cat, catlen);
	return CIPSO_V4_OPT_LEN + catlen;
}

#define ASTRA_OPT_LEN	3	/* w/o level & categories */
/* Store Astra option into a buffer. */
static int write_astra(uint8_t *data, uint16_t len, uint8_t level, uint64_t categories)
{
	uint8_t par[11]; /* to fit 72 by 7 bits */
	int i;

	categories = cpu_to_le64(categories);
	for (i = 0; i < sizeof(par); i++) {
		uint8_t b = (level & 0x7f) << 1;

		level >>= 7;
		level |= (categories & 0x7f) << 1;
		categories >>= 7;
		if (level | categories)
			b |= 1;
		else if (!b)
			break;
		par[i] = b;
	}

	if (ASTRA_OPT_LEN + i > len)
		return -ENOMEM;
	data[0] = IPOPT_SEC;
	data[1] = ASTRA_OPT_LEN + i;
	data[2] = 0b10101011; /* Unclassified */
	memcpy(&data[3], &par, i);
	return ASTRA_OPT_LEN + i;
}

/* Replace packet options with new set. */
static int mangle_options(struct sk_buff *skb, uint8_t *ndata, size_t nlen)
{
	struct iphdr *iph = ip_hdr(skb);
	uint8_t *data = (void *)iph + sizeof(struct iphdr);
	uint16_t len = ip_hdrlen(skb) - sizeof(struct iphdr);
	unsigned int i;

	csum_replace2(&iph->check, *(const __be16 *)(iph), 0);
	csum_replace2(&iph->check, *(const __be16 *)(&iph->tot_len), 0);
	for (i = 0; i < len; i += 2)
		csum_replace2(&iph->check, *(const __be16 *)(&data[i]), 0);

	if (nlen > len) { /* expand header */
		/* data is pointing to network_header which is iphdr
		 * but there is also mac_header before it, don't destroy it */
		skb_push(skb, skb->mac_len);
		if (skb_headroom(skb) < (nlen - len)) {
			if (debug > 1)
				pr_devel("::: skb expanded from %u to %lu bytes (%lu %u)\n",
				    skb_headroom(skb), nlen - len, nlen, len);
			if (pskb_expand_head(skb, nlen - len, 0, GFP_ATOMIC))
				return 0;
		}
		skb_push(skb, nlen - len);
		memmove(skb->data,
		    skb->data + (nlen - len),
		    skb->mac_len + sizeof(struct iphdr));
		skb_reset_mac_header(skb);
		skb_pull(skb, skb->mac_len);
		skb_reset_network_header(skb);
		memcpy(skb->data + sizeof(struct iphdr), ndata, nlen);
		skb_set_transport_header(skb, sizeof(struct iphdr) + nlen);
		if (debug > 1)
			pr_devel("::: packet expanded %lu bytes (%lu %u)\n", nlen - len, nlen, len);

	} else if (nlen < len) { /* shrink header */
		skb_push(skb, skb->mac_len);
		memmove(skb->data + (len - nlen),
		    skb->data,
		    skb->mac_len + sizeof(struct iphdr));
		skb_pull(skb, len - nlen);
		skb_reset_mac_header(skb);
		skb_pull(skb, skb->mac_len);
		skb_reset_network_header(skb);
		memcpy(skb->data + sizeof(struct iphdr), ndata, nlen);
		/* I basically don't touch transport_header */

		if (debug > 1)
			pr_devel("::: packet shortened %lu bytes. [%u]\n", len - nlen, skb->len);
	} else {
		memcpy(data, ndata, len);
		if (debug > 1)
			pr_devel("::: packet replaced\n");
	}

	iph = ip_hdr(skb);
	iph->ihl = (sizeof(struct iphdr) + nlen) / 4;
	iph->tot_len = htons(skb->len);
	csum_replace2(&iph->check, 0, *(const __be16 *)(iph));
	csum_replace2(&iph->check, 0, *(const __be16 *)(&iph->tot_len));

	for (i = 0; i < nlen; i += 2)
		csum_replace2(&iph->check, 0, *(const __be16 *)(&ndata[i]));
	return 1;
}

static void send_parameter_problem(struct sk_buff *skb, uint8_t pointer)
{
	/* "In all cases, if the error is triggered by receipt of an ICMP, the
	 * ICMP is discarded and no response is permitted". */
	if (ip_hdr(skb)->protocol == IPPROTO_ICMP)
		return;
	if (icmp) {
		if (debug > 1)
			pr_devel(": send ICMP Parameter Problem [%u]\n", pointer);
		/* will not send in PREROUTING, because rtable is not filled yet */
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(pointer << 24));
	}
	return;
}

static unsigned int
tripso_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct tripso_info *info = par->targinfo;
	const struct iphdr *iph = ip_hdr(skb);
	const uint8_t *data = (const void *)iph + sizeof(struct iphdr);
	uint16_t len = ip_hdrlen(skb) - sizeof(struct iphdr);
	uint8_t level       = 0;
	uint64_t categories = 0;
	size_t opt_len;
	uint8_t topt[MAX_IPOPTLEN];
	size_t  ti = 0;
	int     sec_err = -1; /* sec option never seen */

	while (len >= 2) {
		int n;

		if (data[IPOPT_OPTVAL] == IPOPT_END)
			break;
		else if (data[IPOPT_OPTVAL] == IPOPT_NOOP) {
			--len;
			++data;
			continue;
		}
		opt_len = data[IPOPT_OLEN];

		/* invalid option length */
		if (opt_len < 2 || opt_len > len)
			return NF_DROP;

		if (data[IPOPT_OPTVAL] == IPOPT_SEC &&
		    info->tr_mode == TRIPSO_CIPSO) {
			/* multiple security options are not allowed */
			if (sec_err != -1)
				goto pproblem;
			if (debug > 1)
				pr_devel("option astra %#x[%x]<%d> %*ph\n",
				    data[IPOPT_OPTVAL], data[IPOPT_OLEN],
				    info->tr_mode, len, data);
			sec_err = !parse_rfc1108_astra(data, len, &level, &categories);
			if (sec_err)
				goto pproblem;
			n = write_cipso(&topt[ti], MAX_IPOPTLEN - ti, level, categories);
			if (n < 0)
				goto pproblem;
			ti += n;
			if (debug > 1)
				pr_devel(":: translated to cipso: %*ph\n", n, topt);
		} else if (data[IPOPT_OPTVAL] == IPOPT_CIPSO &&
		    info->tr_mode == TRIPSO_ASTRA) {
			if (sec_err != -1)
				goto pproblem;
			if (debug > 1)
				pr_devel("option cipso %#x[%x]<%d> %*ph\n",
				    data[IPOPT_OPTVAL], data[IPOPT_OLEN],
				    info->tr_mode, len, data);
			sec_err = !parse_cipso(data, len, &level, &categories);
			if (sec_err)
				goto pproblem;
			n = write_astra(&topt[ti], MAX_IPOPTLEN - ti, level, categories);
			if (n < 0)
				goto pproblem;
			ti += n;
			if (debug > 1)
				pr_devel(":: translated to astra: %*ph\n", n, topt);
		} else {
			memcpy(&topt[ti], data, opt_len);
			ti += opt_len;
		}
		len  -= opt_len;
		data += opt_len;
	}

	if (sec_err == -1)
		return XT_CONTINUE;
	/* otherwise, packet with known security option */

	/* complete options to 32-bit word */
	switch (ti & 3) {
	case 1:
		topt[ti++] = IPOPT_END;
	case 2:
		topt[ti++] = IPOPT_END;
	case 3:
		topt[ti++] = IPOPT_END;
	}

	/* will rewrite whole options set */
	if (!skb_make_writable(skb, ip_hdrlen(skb)) ||
	    !mangle_options(skb, topt, ti))
		return NF_DROP;

	return XT_CONTINUE;

pproblem:
	send_parameter_problem(skb, data - (uint8_t *)iph);
	return NF_DROP;
}

static struct xt_target tripso_tg_reg __read_mostly = {
	.name       = "TRIPSO",
	.family     = NFPROTO_IPV4,
	.target     = tripso_tg,
	.targetsize = sizeof(struct tripso_info),
	.me         = THIS_MODULE,
};

static int __init tripso_init(void)
{
	pr_info("loading " XT_TRIPSO_VERSION ", debug=%d doi=%d icmp=%d\n",
	    debug, doi, icmp);
	return xt_register_target(&tripso_tg_reg);
}

static void __exit tripso_exit(void)
{
	xt_unregister_target(&tripso_tg_reg);
	pr_info("unloaded\n");
}

module_init(tripso_init);
module_exit(tripso_exit);
