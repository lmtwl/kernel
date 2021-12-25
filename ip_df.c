#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <net/pkt_sched.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/kernel_stat.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_bridge.h>
#include <linux/inetdevice.h>
#include <asm/uaccess.h> /* for put_user */
#include <asm/atomic.h>  /* for put_user */

#include "dbg.h"

#define MTU_DST 1400

#define MKIPV4(a, b, c, d) \
    (u32)(((__u8)d & 0xFF) << 24 | ((__u8)c & 0xFF) << 16 | ((__u8)b & 0xFF) << 8 | (a & 0xFF))

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 13, 0)
/*
 include/linux/netfilter.h
typedef unsigned int nf_hookfn(const struct nf_hook_ops *ops,
                   struct sk_buff *skb,
                   const struct net_device *in,
                   const struct net_device *out,
#ifndef __GENKSYMS__
                   const struct nf_hook_state *state
#else
                   int (*okfn)(struct sk_buff *)
#endif
                   );

*/
static unsigned int
nf_ip_input(const struct nf_hook_ops *ops,
            struct sk_buff *skb,
            const struct net_device *in,
            const struct net_device *out,
#ifndef __GENKSYMS__
            const struct nf_hook_state *state
#else
            int (*okfn)(struct sk_buff *)
#endif
)
#else
/*
 typedef unsigned int nf_hookfn(void *priv,
                   struct sk_buff *skb,
                   const struct nf_hook_state *state);
*/

static unsigned int
nf_ip_input(void *priv,
            struct sk_buff *skb,
            const struct nf_hook_state *state)
#endif
{
    struct iphdr *iph = NULL;
    iph = ip_hdr(skb);
    if (iph->frag_off & __constant_htons(IP_DF))
    {
        iph->frag_off &= ~(__constant_htons(IP_DF));
        iph->check = 0;
        iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops nf_hook_ops[] __read_mostly = {
    {
        .hook = nf_ip_input,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)
        .owner = THIS_MODULE,
#endif
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
};

int nf_ip_df_init(void)
{
    int err = 0;
    pr_notice("nf_ip_df_init..\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    err = nf_register_net_hook(&init_net, nf_hook_ops);
#else
    err = nf_register_hooks(nf_hook_ops, ARRAY_SIZE(nf_hook_ops));
#endif
    if (err < 0)
    {
        pr_notice("nf_ip_df_init: can't register hooks.\n");
    }
    pr_emerg("INT_MIN = %d\n", INT_MIN);
    pr_info("ip_mtu: register hooks success.\n");
    return err;
}

void nf_ip_df_fini(void)
{
    pr_notice("nf_ip_df_fini..\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, nf_hook_ops);
#else
    nf_unregister_hooks(nf_hook_ops, ARRAY_SIZE(nf_hook_ops));
#endif
}

module_init(nf_ip_df_init);
module_exit(nf_ip_df_fini);
MODULE_LICENSE("GPL");