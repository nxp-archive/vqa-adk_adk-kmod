/*
 * GPL LICENSE SUMMARY
 *
 *   Copyright (c) 2014-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright (c) 2017 NXP
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
#include <linux/atomic.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/skbuff.h>
#include <net/ip.h>

#include <net/xfrm.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
#define nf_register_net_hooks(a,b,c)	nf_register_hooks(b,c)
#define nf_unregister_net_hooks(a,b,c)	nf_unregister_hooks(b,c)
#endif

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

static unsigned int nsp_misc_ipv4_in(
		void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)

{
	struct net_device  *dev;
	dev = state->out;

	if(strncmp(dev->name, "kni", 3))
		return NF_ACCEPT;

	if(!skb_dst(skb)->xfrm)
		return NF_ACCEPT;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	if (dev_hard_header(skb, dev, ntohs(skb->protocol),
	              dev->broadcast, dev->dev_addr, skb->len) < 0) {
	              kfree_skb(skb);
	              return NF_STOLEN;
	}
	dev_queue_xmit(skb);
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

	dev_queue_xmit(skb);
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

	err = nf_register_net_hooks(
			current->nsproxy->net_ns,
			nsp_misc_hooks, ARRAY_SIZE(nsp_misc_hooks));
	if (err < 0)
		return err;

	dev_add_pack(&nsp_misc_packet);
	return 0;
}

static void __exit nsp_misc_exit(void)
{
	nf_unregister_net_hooks(
			current->nsproxy->net_ns,
			nsp_misc_hooks, ARRAY_SIZE(nsp_misc_hooks));
	dev_remove_pack(&nsp_misc_packet);
}

module_init(nsp_misc_init);
module_exit(nsp_misc_exit);
