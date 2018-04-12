/*
 * GPL LICENSE SUMMARY
 *
 *   Copyright (c) 2014-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright (c) 2017 NXP
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/atomic.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/rwsem.h>
#include <linux/mm.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <net/ip.h>

#include "kni_fifo.h"
#include "kni_dev.h"

#include <net/xfrm.h>

struct pkt_meta_data {
	uint16_t l2_proto; /**< L2 protocol of the packet. Supported protocols
		are ethernet and vlan */
	uint32_t ifid; /**< Interface identifier. This value should be
		interpreted based on the current context of packet processing.
		This points to incoming network device in case of ingress and
		outgoing network device in case of egress context. */
	uint32_t  in_ifid; /**< Incoming interface identifier */

	uint8_t pkt_type; /**< Type of the packet. Supported packets are
		unicast, multicast, broadcast etc. */
	uint32_t ulspi; /*Inbound IPSec SA SPI value */
	uint8_t reserved1; /**< Reserved field and not to be interpreted
		by user */
	uint16_t reserved2; /**< Reserved field and not to be interpreted
		by user */
};

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Intel Corporation/Freescale Semiconductor");
MODULE_DESCRIPTION("Misc kernel module for VortiQa NSP Demo Application");

static int nsp_misc_rcv(struct sk_buff *skb, struct net_device *dev,
                   struct packet_type *pt, struct net_device *orig_dev);


static int nsp_misc_net_tx(struct sk_buff *skb, struct net_device *dev)
{
	uint16_t len = 0;
	unsigned ret;
	struct kni_dev *kni = netdev_priv(dev);
	struct odpfsl_kni_mbuf *pkt_kva = NULL;
	struct odpfsl_kni_mbuf *pkt_va = NULL;

	netif_trans_update(dev);

	/* Check if the length of skb is less than kbuf size */
	if (skb->len > kni->kbuf_size)
		goto drop;

	/**
	 * Check if it has at least one free entry in tx_q and
	 * one entry in alloc_q.
	 */
	if (kni_fifo_free_count(kni->tx_q) == 0 ||
			kni_fifo_count(kni->alloc_q) == 0) {
		/**
		 * If no free entry in tx_q or no entry in alloc_q,
		 * drops skb and goes out.
		 */
		goto drop;
	}

	/* dequeue a kbuf from alloc_q */
	ret = kni_fifo_get(kni->alloc_q, (void **)&pkt_va, 1);
	if (likely(ret == 1)) {
		void *data_kva;

		pkt_kva = (void *)pkt_va - kni->kbuf_va + kni->kbuf_kva;
		data_kva = pkt_kva->data - kni->kbuf_va + kni->kbuf_kva;

		len = skb->len;
		memcpy(data_kva, skb->data, len);
		if (unlikely(len < ETH_ZLEN)) {
			memset(data_kva + len, 0, ETH_ZLEN - len);
			len = ETH_ZLEN;
		}
		pkt_kva->pkt_len = len;
		pkt_kva->data_len = len;
		/* passes gso_size from Kernel to GPP */
		pkt_kva->ol_info = skb_shinfo(skb)->gso_size;

		/* enqueue kbuf into tx_q */
		ret = kni_fifo_put(kni->tx_q, (void **)&pkt_va, 1);
		if (unlikely(ret != 1)) {
			/* Failing should not happen */
			goto drop;
		}
	} else {
		/* Failing should not happen */
		goto drop;
	}

	/* Free skb and update statistics */
	dev_kfree_skb(skb);
	kni->stats.tx_bytes += len;
	kni->stats.tx_packets++;

	return NETDEV_TX_OK;

drop:
	/* Free skb and update statistics */
	dev_kfree_skb(skb);
	kni->stats.tx_dropped++;

	return NETDEV_TX_OK;
}

static unsigned int nsp_misc_ipv4_in(
		void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)

{
	struct net_device  *dev;
	dev = state->out;
	if(strncmp(dev->name, "kni", 2))
	return NF_ACCEPT;

	if(!skb_dst(skb)->xfrm) {
	return NF_ACCEPT;
	}

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	if (dev_hard_header(skb, dev, ntohs(skb->protocol),
	              dev->broadcast, dev->dev_addr, skb->len) < 0) {
	              kfree_skb(skb);
	              return NF_STOLEN;
	}
	nsp_misc_net_tx(skb, dev);
	return NF_STOLEN;
}

static unsigned int nsp_misc_ipv6_in(
		void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)

{
	struct net_device  *dev;
	int type;

	type = ipv6_addr_type(&ipv6_hdr(skb)->daddr);
	if (type & IPV6_ADDR_MULTICAST)
		return NF_ACCEPT;

	dev = state->out;
	if(strncmp(dev->name, "kni", 3))
		return NF_ACCEPT;

	if(!skb_dst(skb)->xfrm)
		return NF_ACCEPT;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IPV6);
	if (dev_hard_header(skb, dev, ntohs(skb->protocol),
		dev->broadcast, dev->dev_addr, skb->len) < 0) {
		kfree_skb(skb);
		return NF_STOLEN;
	}

	nsp_misc_net_tx(skb, dev);
	return NF_STOLEN;
}

static int nsp_misc_rcv(struct sk_buff *skb, struct net_device *dev,
                   struct packet_type *pt, struct net_device *orig_dev)
{
	unsigned char *data;
	struct pkt_meta_data *meta;
	struct xfrm_state *state = 0;

	data = skb->data;

	meta =	(struct pkt_meta_data *) (data);

	data = __skb_pull(skb, sizeof(*meta));
	skb->protocol = eth_type_trans(skb, skb->dev);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

	if(skb->protocol == htons(ETH_P_IPV6))
		state = xfrm_state_lookup_byspi(dev_net(skb->dev),
							meta->ulspi,AF_INET6);
	else
		state = xfrm_state_lookup_byspi(dev_net(skb->dev),
							meta->ulspi,AF_INET);

	if(state){
		skb->sp = secpath_dup(NULL);
		skb->sp->xvec[skb->sp->len++] = state;
	}
	netif_rx(skb);
	return 0;
}

#define BNSP_CUST_HEADER 0x8888

static struct packet_type nsp_misc_packet __read_mostly = {
        .type = cpu_to_be16(BNSP_CUST_HEADER),
        .func = nsp_misc_rcv,
};

static struct nf_hook_ops nsp_misc_hooks[] __read_mostly = {
	{
		.hook		= nsp_misc_ipv4_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority       = 1,
	},
	{
		.hook		= nsp_misc_ipv6_in,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority       = 1,
	},
};

static int __init nsp_misc_init(void)
{
	int err;

	err = nf_register_hooks(nsp_misc_hooks, ARRAY_SIZE(nsp_misc_hooks));
	if (err < 0)
		return err;

	dev_add_pack(&nsp_misc_packet);
	return 0;
}

static void __exit nsp_misc_exit(void)
{
	nf_unregister_hooks(nsp_misc_hooks, ARRAY_SIZE(nsp_misc_hooks));
	dev_remove_pack(&nsp_misc_packet);
}

module_init(nsp_misc_init);
module_exit(nsp_misc_exit);
