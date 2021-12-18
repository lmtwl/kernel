#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops *nfho = NULL;

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    __be32 saddr, daddr;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    if (!skb)
        return NF_ACCEPT;
    iph = ip_hdr(skb);

     saddr = iph->saddr;
     daddr = iph->daddr;
    if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        //printk(KERN_INFO "udp port %d --- %d\n",ntohs(udph->source),ntohs(udph->dest));
        printk(KERN_INFO "udp:%pI4:%d---%pI4:%d\n",(unsigned char *)(&saddr),ntohs(udph->source),(unsigned char *)(&daddr),ntohs(udph->dest));
        return NF_ACCEPT;
    }
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        //printk(KERN_INFO "tcp port %d --- %d\n",ntohs(tcph->source),ntohs(tcph->dest));
        printk(KERN_INFO "tcp:%pI4:%d---%pI4:%d\n",(unsigned char *)(&saddr),ntohs(tcph->source),(unsigned char *)(&daddr),ntohs(tcph->dest));
        
        return NF_ACCEPT;
    }
    //printk(KERN_INFO "ip\n");
    return NF_ACCEPT;
}

static int __init pcap_init(void)
{
    nfho = (struct nf_hook_ops*) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho->hook = (nf_hookfn*) hook_func;
    nfho->hooknum = NF_INET_PRE_ROUTING;
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nfho);
    return 0;
}

static void __exit pcap_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
}

module_init(pcap_init);
module_exit(pcap_exit);
